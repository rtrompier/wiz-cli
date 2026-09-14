mod client;
mod commands;
mod format;
mod ids;
mod time;

use clap::{Args, Parser, Subcommand};

use commands::issue_engine::IssueFilterArgs;

#[derive(Parser)]
#[command(
    name = "wiz-cli",
    version,
    about = "CLI for the Wiz GraphQL API",
    long_about = "A macOS-first CLI for reading and updating Wiz issues through GraphQL.\n\n\
                  Requires WIZ_CLIENT_ID, WIZ_CLIENT_SECRET and WIZ_API_URL (your tenant's GraphQL endpoint) for network operations. WIZ_AUTH_URL overrides the default token endpoint.\n\n\
                  Output is JSON on stdout by default. Use -H for human-readable tables. Errors go to stderr."
)]
struct Cli {
    /// Human-readable table output instead of JSON
    #[arg(short = 'H', long, global = true)]
    human: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args)]
struct ListArgs {
    #[command(flatten)]
    filters: IssueFilterArgs,

    /// Number of results to return
    #[arg(short = 'n', long = "number", default_value = "20")]
    number: usize,

    /// Fetch every page and ignore --number
    #[arg(long)]
    all: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// List issues of any type
    Issues(ListArgs),

    /// List threat-detection issues with threat details
    Threats(ListArgs),

    /// Show one issue
    Issue {
        /// Issue ID
        id: String,
    },

    /// Show one threat-detection issue with threat details
    Threat {
        /// Issue ID
        id: String,
    },

    /// List evidence records for an issue
    #[command(
        long_about = "List evidence records for an issue.\n\nThe evidence query schema is unverified against a live tenant. If Wiz rejects it, confirm the field names in the Wiz API Explorer and use `wiz-cli graphql` as a fallback."
    )]
    Evidence {
        /// Issue ID
        id: String,
    },

    /// List history events for an issue
    #[command(
        long_about = "List history events for an issue.\n\nThe history query schema is unverified against a live tenant. If Wiz rejects it, confirm the field names in the Wiz API Explorer and use `wiz-cli graphql` as a fallback."
    )]
    History {
        /// Issue ID
        id: String,
    },

    /// Close issues as rejected or resolved
    Close {
        /// Issue IDs: one ID, comma-separated IDs, or '-' for newline-separated stdin
        #[arg(allow_hyphen_values = true)]
        ids: String,

        #[arg(long, long_help = commands::close::REASON_HELP)]
        reason: String,

        /// Add this note with the status change (required by the API for a REJECTED close)
        #[arg(long)]
        note: Option<String>,

        /// Set rejection expiry to this many days from now
        #[arg(long)]
        rejection_expires_days: Option<u64>,

        /// Print GraphQL operations without credentials or network access
        #[arg(long)]
        dry_run: bool,
    },

    /// Change issue status to OPEN or IN_PROGRESS
    Status {
        /// Issue IDs: one ID, comma-separated IDs, or '-' for newline-separated stdin
        #[arg(allow_hyphen_values = true)]
        ids: String,

        /// New status: OPEN or IN_PROGRESS
        status: String,

        /// Print GraphQL operations without credentials or network access
        #[arg(long)]
        dry_run: bool,
    },

    /// Add a note to issues
    Note {
        /// Issue IDs: one ID, comma-separated IDs, or '-' for newline-separated stdin
        #[arg(allow_hyphen_values = true)]
        ids: String,

        /// Note text
        text: String,

        /// Print GraphQL operations without credentials or network access
        #[arg(long)]
        dry_run: bool,
    },

    /// Assign issues to an email address
    Assign {
        /// Issue IDs: one ID, comma-separated IDs, or '-' for newline-separated stdin
        #[arg(allow_hyphen_values = true)]
        ids: String,

        /// Assignee email address
        email: String,

        /// Print GraphQL operations without credentials or network access
        #[arg(long)]
        dry_run: bool,
    },

    /// Execute a raw GraphQL query
    Graphql {
        /// GraphQL query string
        query: String,

        /// Variables as a JSON object
        #[arg(long, value_name = "JSON")]
        vars: Option<String>,
    },

    /// Show service account identity and granted scopes without calling GraphQL
    Whoami,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Issues(args) => {
            commands::issues::run(&args.filters, args.number, args.all, false, cli.human).await
        }
        Commands::Threats(args) => {
            commands::threats::run(&args.filters, args.number, args.all, cli.human).await
        }
        Commands::Issue { id } => commands::issue::run(&id, false, cli.human).await,
        Commands::Threat { id } => commands::threat::run(&id, cli.human).await,
        Commands::Evidence { id } => commands::evidence::run(&id, cli.human).await,
        Commands::History { id } => commands::history::run(&id, cli.human).await,
        Commands::Close {
            ids,
            reason,
            note,
            rejection_expires_days,
            dry_run,
        } => {
            commands::close::run(
                &ids,
                &reason,
                note.as_deref(),
                rejection_expires_days,
                dry_run,
                cli.human,
            )
            .await
        }
        Commands::Status {
            ids,
            status,
            dry_run,
        } => commands::status::run(&ids, &status, dry_run, cli.human).await,
        Commands::Note { ids, text, dry_run } => {
            commands::note::run(&ids, &text, dry_run, cli.human).await
        }
        Commands::Assign {
            ids,
            email,
            dry_run,
        } => commands::assign::run(&ids, &email, dry_run, cli.human).await,
        Commands::Graphql { query, vars } => {
            commands::graphql::run(&query, vars.as_deref(), cli.human).await
        }
        Commands::Whoami => commands::whoami::run(cli.human).await,
    };

    if let Err(error) = result {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}
