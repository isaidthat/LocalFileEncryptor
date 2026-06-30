pub fn input(question:&str) -> std::io::Result<String> {
    let mut s = String::new();
    println!("{question}");
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_owned())
}
