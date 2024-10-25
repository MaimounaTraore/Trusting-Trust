use std::env;
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

    //Here we are checking if the database file specified in the command exists, if not, the program will return "Databsae file does not exist"
    if !Path::new(filename).exists(){
        eprintln!("Error! Password database not found!");
        return Err("Database file does not exist".into());
    }

    let (username, password) = get_user_input();
    match search_username_in_csv(filename, &username)?{
        Some(stored_password_hash)=>{
        // Here, we are verifying the password enterred by the user and the hashed password that is already stored in our db.csv
       if verify_password(&password, &stored_password_hash){
        //If they match, we grant access to the user
        println!("Access granted!");
       } else{
        //If the two passwords do not match, we deny access to the user
        eprintln!("Error! Access denied!");
       }
    },
    None => {
        //Here we are handling the case where the username was not found in the database
        println!("Error! Access denied!");
        }
    }
    Ok(())
    
}
//This function will search in the database the username enterred by the user 
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

//This function gets all the input, username and password, froom the user through the command line
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

//This function makes sure that the password enterred by the user for a specific username matches the password dstored in the databse.
fn verify_password(password: &str, stored_hash: &str) -> bool{
    // println!("*********password: '{}', *******stored_hash: '{}'", password, stored_hash);//We were just testing here to see if we were receiving the expected password and stored_hash
    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(stored_hash).unwrap(); 

    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok() 
}

//----------------------  TEST FUNCTIONS -----------------------------------

#[cfg(test)]
mod tests{

    use super::*;
    use std::fs::File;
    use std::io::Write;
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    use rand::rngs::OsRng;

    //Here we are creating a test database with dummy data wthat will help us run the tests 
    fn create_test_db() -> std::io::Result<()> {
        let mut file = File::create("test_db.csv")?;
        writeln!(file, "\"testuser\",\"$argon2i$v=19$m=4096,t=3,p=1$some_salt$hashedpassword\"")?;
        writeln!(file, "\"otheruser\",\"$argon2i$v=19$m=4096,t=3,p=1$some_salt$otherhashedpassword\"")?;
        Ok(())
    }

    #[test]
    fn test_search_username_in_csv() {
        // Creating the dummy database
        create_test_db().expect("Failed to create test DB");

        // Existing user
        let result = search_username_in_csv("test_db.csv", "testuser");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("$argon2i$v=19$m=4096,t=3,p=1$some_salt$hashedpassword".to_string()));

        // Non-existent user
        let result = search_username_in_csv("test_db.csv", "nonexistent");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);

        // Here we are making sure that after this step the dummy databse is removed
        std::fs::remove_file("test_db.csv").expect("Failed to delete test DB");
    }

    #[test]

    fn test_verify_password() {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let password = "mypassword";
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();

        assert!(verify_password(password, &password_hash));
        assert!(!verify_password("wrongpassword", &password_hash));
    }
}