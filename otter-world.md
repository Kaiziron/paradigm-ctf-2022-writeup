# OTTER-WORLD (242.4 points, sanity check)

Solved by: Kaiziron

Team: D53_H473r5 

### Description :
```
DESCRIPTION
Otter World!


ACCESS
nc 34.72.24.70 8080


RESOURCES
https://github.com/paradigmxyz/paradigm-ctf-infrastructure
/resources/otter-world.tar.gz
```

This challenge is just a sanity check, just complete the given solve framework for the solana ctf framework to solve it.


This rust file (client/framework/chall/programs/chall/src/lib.rs) shows the `get_flag` function :
```rust
...
#[program]
pub mod chall {
    use super::*;

    pub fn get_flag(_ctx: Context<GetFlag>, magic: u64) -> Result<()> {
        assert!(magic == 0x1337 * 0x7331);

        Ok(())
    }

}
...
```

Just call `get_flag` with `0x1337 * 0x7331` to solve it.

In the files given, there is a solve framework, just modify the line calling the function to solve it

(client/framework-solve/solve/programs/solve/src/lib.rs)

```rust
        chall::cpi::get_flag(cpi_ctx, 0x1337 /* TODO */)?;
```

```rust
...
#[program]
pub mod solve {
    use super::*;

    pub fn get_flag(ctx: Context<GetFlag>) -> Result<()> {

        let cpi_accounts = chall::cpi::accounts::GetFlag {
            flag: ctx.accounts.flag.clone(),
            payer: ctx.accounts.payer.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            rent: ctx.accounts.rent.to_account_info(),
        };

        let cpi_ctx = CpiContext::new(ctx.accounts.chall.to_account_info(), cpi_accounts);

        chall::cpi::get_flag(cpi_ctx, 0x1337 * 0x7331)?;

        Ok(())
    }
}
...
```

Then just change the address it will connect to, to the instance we deployed.
(client/framework-solve/src/main.rs) :
```rust
...
fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("34.72.24.70:8080")?;
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    let mut line = String::new();
...
```
Then just run `setup.sh` to setup docker and compile the solve framework, and run `run.sh` inside the docker instance to solve it.


### Flag :
```
...
warning: `solve` (lib) generated 1 warning
   Compiling solve-framework v0.1.0 (/work/framework-solve)
    Finished release [optimized] target(s) in 2.72s
     Running `target/release/solve-framework`
congrats!
flag: "PCTF{0tt3r_w0r1d_8c01j3}"
➜  /work 
```