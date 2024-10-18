use std::env;
// use std::io;
use std::fs::File;
use std::path::Path;
use std::error::Error;
use csv::StringRecord;
use csv::ReaderBuilder;
use std::io::{self, Write};
use argon2::{self, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};



fn main() -> Result<(), Box<dyn Error>> {

    let args : Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Error! password database  not found!");
        return Err("No database file provided".into());

    }
    let filename = &args[1];

    //Here I will check if teh database file exists
    if !Path::new(filename).exists(){
        eprintln!("Error! Password database not found!");
        return Err("Database file does not exist".into());
    }

    let (username, password) = get_user_input();
    match search_username_in_csv(filename, &username)?{
        Some(stored_password_hash)=>{
        // Here, we are verifying th epassword enterred by the user and the password that is already stored in our db.csv
       if verify_password(&password, &stored_password_hash){
        println!("Access granted!");
       } else{
        eprintln!("Error! Access denied!");
       }
    },
    None => {
        //Here we have the case where the username was not found
        println!("Error! Access denied!");
        }
    }
    Ok(())
    
}

fn search_username_in_csv(filename: &str, username: &str) -> Result<Option<String>, Box<dyn Error>> {
    let file = File::open(filename)?;
    let mut rdr = ReaderBuilder::new().has_headers(false).from_reader(file);
    
    for result in rdr.records(){
        let record = result?;

        if let Some (stored_username) = record.get(0){
            let stored_username = stored_username.trim_matches('"').trim();
            if stored_username == username{
                if let Some(password_hash) = record.get(1){
                    return Ok(Some(password_hash.trim_matches('"').to_string()));
                }
            }

        }
    }
    Ok(None)
}


fn get_user_input() -> (String, String){
    let mut username = String::new();
    let mut password = String::new();

    print!("Enter username: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut username).unwrap();
    let username = username.trim().to_string();

    print!("Enter password: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut password).unwrap();
    let password = password.trim().to_string();

    (username, password)
}

fn verify_password(password: &str, stored_hash: &str) -> bool{
    println!("*********password: '{}', *******stored_hash: '{}'", password, stored_hash);//I am just testing here to s receiving the expected password and stored_hash
    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(stored_hash).unwrap(); 

    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok() 
}