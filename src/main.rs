use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{self, BufRead},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use domain::{
    base::{
        iana::{Class, Rcode},
        message_builder::AnswerBuilder,
        name::Label,
        Dname, Message, MessageBuilder, ParsedDname, ToDname,
    },
    rdata::A,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::RwLock,
    time,
};

type DenyIps = Arc<RwLock<Vec<Ipv4Addr>>>;
type Whitelist = Arc<RwLock<Vec<Dname<Vec<u8>>>>>;
type Cache = Arc<RwLock<HashMap<Dname<Vec<u8>>, Ipv4Addr>>>;
type UpStreamAddr = Arc<RwLock<SocketAddr>>;

fn gen_answerbuilder(
    msg: &Message<Vec<u8>>,
    rcode: Rcode,
) -> Result<AnswerBuilder<Vec<u8>>, String> {
    let answerbuilder = MessageBuilder::from_target(Vec::<u8>::with_capacity(50))
        .map_err(|_| "create dns reply message err".to_string())?
        .start_answer(msg, rcode)
        .map_err(|_| "create dns reply message err".to_string())?;
    Ok(answerbuilder)
}

async fn check_deny_ip_and_reply(
    addr: &SocketAddr,
    ips: DenyIps,
    msg: &Message<Vec<u8>>,
    socket: Arc<UdpSocket>,
) -> Result<(), String> {
    let deny_ips = ips.read().await;
    for line in deny_ips.iter() {
        if line == &addr.ip() {
            let reply = gen_answerbuilder(msg, Rcode::Refused)?
                .into_message()
                .into_octets();
            socket
                .send_to(&reply, addr)
                .await
                .map_err(|_| "response the upstream query result fail!".to_string())?;
            return Err(format!("{}", addr));
        }
    }
    Ok(())
}

async fn check_reversequery_and_reply(
    addr: &SocketAddr,
    parsed_dname: &ParsedDname<&Vec<u8>>,
    reverse_name_last: &Label,
    msg: &Message<Vec<u8>>,
    socket: Arc<UdpSocket>,
) -> Result<(), String> {
    let mut i = parsed_dname.iter();
    i.next_back();
    let l = i.next_back();
    if let Some(last) = l {
        if last == reverse_name_last {
            let reply = gen_answerbuilder(msg, Rcode::NXDomain)?
                .into_message()
                .into_octets();

            socket
                .send_to(&reply, addr)
                .await
                .map_err(|_| "response the upstream query result fail!".to_string())?;

            return Err(format!(
                "{} query {} , is reverse query , not support , deny!",
                addr, parsed_dname
            ));
        }
    }
    Ok(())
}

async fn check_whitelist_and_reply(
    addr: &SocketAddr,
    list: Whitelist,
    parsed_dname: &ParsedDname<&Vec<u8>>,
    fack_ip: Ipv4Addr,
    msg: &Message<Vec<u8>>,
    socket: Arc<UdpSocket>,
) -> Result<(), String> {
    for dname in list.read().await.iter() {
        if parsed_dname.ends_with(dname) {
            return Ok(());
        }
    }

    reply(addr, msg, fack_ip, 3600, socket).await?;

    Err(format!(
        "{} query {} , not in whitelist , deny!",
        addr, parsed_dname
    ))
}

async fn reply(
    addr: &SocketAddr,
    msg: &Message<Vec<u8>>,
    ipv4: Ipv4Addr,
    ttl: u32,
    socket: Arc<UdpSocket>,
) -> Result<(), String> {
    let mut answerbuilder = gen_answerbuilder(msg, Rcode::NoError)?;

    answerbuilder
        .push((Dname::root_ref(), Class::In, ttl, A::new(ipv4)))
        .map_err(|_| "push answer ip to rely message builder fail!".to_string())?;

    let reply = answerbuilder.into_message().into_octets();
    socket
        .send_to(&reply, addr)
        .await
        .map_err(|_| "response the upstream query result fail!".to_string())?;
    Ok(())
}

async fn reply_from_upstream(
    upstream_addr: Arc<RwLock<SocketAddr>>,
    addr: &SocketAddr,
    msg: &Message<Vec<u8>>,
    socket: Arc<UdpSocket>,
) -> Result<(), String> {
    let local = UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("couldn't bind to address");

    let upstream_addr = upstream_addr.read().await;
    local
        .connect(*upstream_addr)
        .await
        .expect("connect to upstream addr fail");

    local
        .send(msg.as_octets())
        .await
        .expect("send come data to upstream error");

    let mut recv_buf = [0u8; 512];
    if let Ok(result) =
        time::timeout(time::Duration::from_secs(8), local.recv_from(&mut recv_buf)).await
    {
        match result {
            Ok((len, _)) => {
                let reply = recv_buf[..len].to_vec();
                socket
                    .send_to(&reply, addr)
                    .await
                    .map_err(|_| "response the upstream query result fail!".to_string())?;
                Ok(())
            }
            Err(_) => return Err("upstream query recv data err!".to_string()),
        }
    } else {
        let reply = gen_answerbuilder(msg, Rcode::ServFail)?
            .into_message()
            .into_octets();
        socket
            .send_to(&reply, addr)
            .await
            .map_err(|_| "response the upstream query result fail!".to_string())?;
        Err("upstream query timeout 8 sec!".to_string())
    }
}

#[tokio::main]
async fn main() {
    let (denyips, whitelist, cache, upstream_addr) = init();

    let tcp = TcpListener::bind("0.0.0.0:53")
        .await
        .expect("bind tcp socket to 0.0.0.0:53 fail!");

    let udp = UdpSocket::bind("0.0.0.0:53")
        .await
        .expect("bind udp socket to 0.0.0.0:53 fail!");

    let tcp_denyips = denyips.clone();
    let tcp_whitelist = whitelist.clone();
    let tcp_cache = cache.clone();
    let reverse_name_last_lable =
        Label::from_slice(b"arpa").expect("parse reverse name last lable err!");
    let fack_ip = Ipv4Addr::from_str("1.2.3.4").expect("parse fack ip err!");
    tokio::spawn(async move {
        loop {
            let (stream, addr) = tcp.accept().await.expect("tcp accept a stream fail!");
            //dynamic change dns config
        }
    });

    let mut buf = vec![0; 512];
    let udp = Arc::new(udp);
    let udp_denyips = denyips.clone();
    let udp_whitelist = whitelist.clone();
    let udp_cache = cache.clone();
    loop {
        let udp = udp.clone();
        let denyips = udp_denyips.clone();
        let whitelist = udp_whitelist.clone();
        let cache = udp_cache.clone();
        let upstream_addr = upstream_addr.clone();

        if let Ok((len, addr)) = udp.recv_from(&mut buf).await {
            let buf = buf[..len].to_vec();
            tokio::spawn(async move {
                if let Err(err) = async {
                    let msg = Message::from_octets(buf)
                        .map_err(|_| "parse udp data to Message<Vec<u8>> fail".to_string())?;

                    check_deny_ip_and_reply(&addr, denyips, &msg, udp.clone()).await?;

                    let question = msg
                        .sole_question()
                        .map_err(|_| "parse dns packet question section err".to_string())?;

                    let parsed_dname = question.qname();

                    check_reversequery_and_reply(
                        &addr,
                        parsed_dname,
                        &reverse_name_last_lable,
                        &msg,
                        udp.clone(),
                    )
                    .await?;

                    check_whitelist_and_reply(
                        &addr,
                        whitelist,
                        parsed_dname,
                        fack_ip,
                        &msg,
                        udp.clone(),
                    )
                    .await?;

                    let dname: Dname<Vec<u8>> = parsed_dname
                        .to_dname()
                        .map_err(|_| "parse question section qname to dname fail".to_string())?;

                    match cache.read().await.get(&dname) {
                        Some(ip) => reply(&addr, &msg, ip.to_owned(), 86400, udp.clone()).await?,
                        None => {
                            reply_from_upstream(upstream_addr.clone(), &addr, &msg, udp.clone())
                                .await?
                        }
                    };

                    Ok::<(), String>(())
                }
                .await
                {
                    eprintln!("{}", err);
                }
            });
        } else {
            continue;
        }
    }
}

fn init() -> (DenyIps, Whitelist, Cache, UpStreamAddr) {
    let upstream_addr_str = if let Some(addr_str) = env::args().nth(1) {
        addr_str
    } else {
        "10.1.6.10:53".to_owned()
    };
    println!("upstream dns server is : {}", upstream_addr_str);

    let upstream_addr =
        SocketAddr::from_str(&upstream_addr_str).expect("parse arg to upstream addr fail!");
    let locked_upstream_addr = Arc::new(RwLock::new(upstream_addr));

    let deny_ip_list_path = "deny_ip_list.txt";
    let white_list_path = "white_list.txt";
    let dns_cache_path = "dns_cache.txt";

    let read_lines = |filename| -> io::Result<io::Lines<io::BufReader<File>>> {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    };

    let parse_line_to_hashmap = |line: &str| -> Result<(Dname<Vec<u8>>, Ipv4Addr), &'static str> {
        let mut s = line.trim().split(' ');

        let n = s.next().ok_or("missing danme field in this line")?;
        let key = Dname::<Vec<u8>>::from_str(n).map_err(|_| "parse dname  err")?;

        let i = s.next().ok_or("missing ip field in line")?;
        let ip = Ipv4Addr::from_str(i).map_err(|_| "parse ip field err")?;

        Ok((key, ip))
    };

    let mut deny_ips = Vec::new();
    if let Ok(lines) = read_lines(deny_ip_list_path) {
        for (index, line) in lines.enumerate() {
            if let Ok(line) = line {
                let line = line.trim();
                if !line.is_empty() {
                    match Ipv4Addr::from_str(&line) {
                        Ok(a) => deny_ips.push(a),
                        Err(_) => {
                            panic!("parse deny_ip_list line {} to ipaddr err!", index);
                        }
                    };
                }
            }
        }
    }
    println!("deny_ips{:?}", deny_ips);
    let locked_deny_ips = Arc::new(RwLock::new(deny_ips));

    let mut whitelist = Vec::new();
    if let Ok(lines) = read_lines(white_list_path) {
        for (index, line) in lines.enumerate() {
            if let Ok(line) = line {
                let line = line.trim();
                if !line.is_empty() {
                    match Dname::<Vec<u8>>::from_str(&format!("{}.", line)) {
                        Ok(d) => whitelist.push(d),
                        Err(_) => {
                            panic!("parse blacklist file , line {} to ipv4addr err!", index);
                        }
                    };
                }
            }
        }
    }
    println!("whitelist:{:?}", whitelist);
    let locked_whitelist = Arc::new(RwLock::new(whitelist));

    let mut cache = HashMap::new();
    if let Ok(lines) = read_lines(dns_cache_path) {
        for (index, line) in lines.enumerate() {
            if let Ok(line) = line {
                let line = line.trim();
                if !line.is_empty() {
                    match parse_line_to_hashmap(line) {
                        Ok((k, v)) => {
                            cache.insert(k, v);
                        }
                        Err(s) => panic!("parse dns_cache file , line {} err!, {}", index, s),
                    }
                }
            }
        }
    }
    println!("{:?}", cache);
    let locked_cache = Arc::new(RwLock::new(cache));

    (
        locked_deny_ips,
        locked_whitelist,
        locked_cache,
        locked_upstream_addr,
    )
}
