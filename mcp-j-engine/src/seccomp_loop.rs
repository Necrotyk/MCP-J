pub struct SeccompLoop {
    // seccomp loop fields
}

impl SeccompLoop {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn run(&self) {
        println!("Seccomp loop running");
    }
}
