use percolator_prog::constants::*;
use percolator_prog::zc::ACCOUNTS_OFFSET;
fn main() {
    println!("HEADER_LEN = {}", HEADER_LEN);
    println!("CONFIG_LEN = {}", CONFIG_LEN);
    println!("ENGINE_OFF = {}", ENGINE_OFF);
    println!("ENGINE_LEN = {}", ENGINE_LEN);
    println!("SLAB_LEN = {}", SLAB_LEN);
    println!("ACCOUNTS_OFFSET (in engine) = {}", ACCOUNTS_OFFSET);
    println!("ACCOUNTS_SECTION_OFF = {}", ENGINE_OFF + ACCOUNTS_OFFSET);
}
