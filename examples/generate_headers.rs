use sframe::{
    header::Header,
    header::{Deserialization, Serialization},
    util::bin2string,
};
fn main() {
    let limit = std::env::args()
        .nth(1)
        .and_then(|x| x.parse::<u16>().ok())
        .unwrap_or(10);

    for k in 0..limit as u64 {
        let header = Header::new(k.try_into().unwrap());
        let mut buffer = vec![0u8; 4];
        header.serialize(&mut buffer).unwrap();
        println!("{:}", bin2string(&buffer));
        println!("{:?}", Header::deserialize(&buffer));
    }
}
