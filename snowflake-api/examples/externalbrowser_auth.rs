extern crate snowflake_api;

use anyhow::Result;
use arrow::util::pretty::pretty_format_batches;
use clap::Parser;

use snowflake_api::{QueryResult, SnowflakeApi};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// <account_identifier> in Snowflake format, uppercase
    #[arg(short, long)]
    account_identifier: String,

    /// Database name
    #[arg(short, long)]
    database: Option<String>,

    /// Schema name
    #[arg(long)]
    schema: Option<String>,

    /// Warehouse
    #[arg(short, long)]
    warehouse: Option<String>,

    /// username for external browser authentication
    #[arg(short, long)]
    username: String,

    /// role which user will assume
    #[arg(short, long)]
    role: Option<String>,

    /// sql statement to execute and print result from
    #[arg(long)]
    sql: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let args = Args::parse();

    println!("Initiating external browser authentication...");
    println!("A browser window will open for you to authenticate.");

    let mut api = SnowflakeApi::with_externalbrowser_auth(
        &args.account_identifier,
        args.warehouse.as_deref(),
        args.database.as_deref(),
        args.schema.as_deref(),
        &args.username,
        args.role.as_deref(),
    )?;

    println!("Executing query...");
    let res = api.exec(&args.sql).await?;

    match res {
        QueryResult::Arrow(batches) => {
            println!("{}", pretty_format_batches(&batches).unwrap());
        }
        QueryResult::Json(j) => {
            println!("{j}");
        }
        QueryResult::Empty => {
            println!("Query finished successfully")
        }
    }

    api.close_session().await?;

    Ok(())
}
