extern crate tokio;
use colored::Colorize;
use hyper::client::*;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use mime_guess::from_path;
use slack_morphism::prelude::*;

//use rsb_derive::Builder;

use clap::{Parser, Subcommand};
use std::{
    collections::HashMap,
    fmt::Display,
    fs,
    io::Cursor,
    path::PathBuf,
    sync::{LazyLock, Mutex},
};

static USER_HASH: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
/// This is a simple slack file upload utility.
struct SlackConfig {
    /// Which channel to upload to. Either a channel name (todo!) or the Channel ID
    // #[arg(short, long, value_name = "SLACK_CHANNEL", env)]
    // slack_channel: String,

    /// Your OAuth token.
    #[arg(short, long, value_name = "BEARER_TOKEN", env)]
    bearer_token: String,

    /// Path to the file to upload
    // #[arg(short, long, value_name = "UPLOAD_FILE", env)]
    // upload_file: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Adds files to myapp
    Put {
        local: PathBuf,
        remote: PathBuf,
    },
    Get {
        remote_id: String,
        local: Option<PathBuf>,
    },
    Delete {
        remote: PathBuf,
    },
    Stat {
        remote: PathBuf,
    },
    Ls {
        remote: Option<PathBuf>,
    },
    Cd {
        remote: Option<PathBuf>,
    },
}

async fn rest_file_upload(
    cfg: &SlackConfig,
    local: &PathBuf,
    remote: &PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = SlackClient::new(SlackClientHyperConnector::new()?);
    let token_value: SlackApiTokenValue = cfg.bearer_token.clone().into();
    let token: SlackApiToken = SlackApiToken::new(token_value);
    let session = client.open_session(&token);
    //let test_content: String = "test-content".into();
    let req = SlackApiConversationsListRequest::new();
    let convos = session.conversations_list(&req).await?.channels;

    let channel_name = match &remote.strip_prefix("/") {
        Ok(path) => path.clone(),
        Err(_) => remote.as_path().clone(),
    };
    let channel_name = channel_name
        .as_os_str()
        .to_str()
        .expect("Couldn't convert path")
        .to_string();

    let convos = convos
        .iter()
        .filter(|convo| convo.name.is_some() && convo.name.clone().unwrap() == channel_name)
        .collect::<Vec<&SlackChannelInfo>>();

    if convos.len() > 0 {
        let cid = convos.last().clone().unwrap().id.clone();
        let filename = local
            .file_name()
            .expect("No filename?!")
            .to_str()
            .expect("Can't normalize name");
        // .to_string();
        let content = fs::read(local.as_path())?;
        let get_upload_url_req =
            SlackApiFilesGetUploadUrlExternalRequest::new(filename.into(), content.len());
        let upload_url_resp = session.get_upload_url_external(&get_upload_url_req).await?;
        //println!("get url resp: {:#?}", &upload_url_resp);
        let mime = from_path(local.as_path())
            .first()
            .expect("Failed to guess mime type");
        let mime = mime.essence_str();
        let file_upload_req = SlackApiFilesUploadViaUrlRequest::new(
            upload_url_resp.upload_url,
            content.into(),
            mime.into(),
        );
        //println!("My guessed mime type is: {}", mime);

        let file_upload_resp = session.files_upload_via_url(&file_upload_req).await?;
        //println!("file_upload_resp: {:#?}", &file_upload_resp);

        let complete_file_upload_req =
            SlackApiFilesCompleteUploadExternalRequest::new(vec![SlackApiFilesComplete::new(
                upload_url_resp.file_id,
            )])
            .with_channel_id(cid);

        let complete_file_upload_resp = session
            .files_complete_upload_external(&complete_file_upload_req)
            .await?;
        //println!(
        //    "complete_file_upload_resp: {:#?}",
        //    &complete_file_upload_resp
        //);

        Ok(())
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Destination not found.",
        )))
    }
}

async fn get_user_name_by_id(cfg: &SlackConfig, user_id: &SlackUserId) -> String {
    if USER_HASH.lock().unwrap().contains_key(&user_id.0) {
        USER_HASH.lock().unwrap().get(&user_id.0).unwrap().clone()
    } else {
        let client =
            SlackClient::new(SlackClientHyperConnector::new().expect("Failed to get client!"));
        let token_value: SlackApiTokenValue = cfg.bearer_token.clone().into();
        let token: SlackApiToken = SlackApiToken::new(token_value);
        let session = client.open_session(&token);
        let req = SlackApiUsersInfoRequest::new(user_id.clone());
        let user_deets = session.users_info(&req).await;
        if let Ok(user_resp) = user_deets {
            let uname = user_resp.user.name.unwrap_or("N/A".to_string()).clone();
            USER_HASH
                .lock()
                .as_mut()
                .unwrap()
                .insert(user_id.0.clone(), uname.clone());
            uname.clone()
        } else {
            //println!("User response: {:?}", &user_deets);
            "N/A".to_string()
        }
    }
}

async fn list_channels(
    cfg: &SlackConfig,
    remote: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = SlackClient::new(SlackClientHyperConnector::new()?);
    let token_value: SlackApiTokenValue = cfg.bearer_token.clone().into();
    let token: SlackApiToken = SlackApiToken::new(token_value);
    let session = client.open_session(&token);
    let req = SlackApiConversationsListRequest::new();

    let convos = session.conversations_list(&req).await?;
    //println!("Convos: {:?}", &convos);
    let remote = remote.clone();

    if remote.is_none()
        || remote
            .clone()
            .is_some_and(|r| r.as_path().to_str().expect("Failed to convert path...") == "/")
    {
        for channel in &convos.channels {
            //println!("Channel: {:?}", channel.name);
            //println!("\tid: {:?}", channel.id);
            println!(
                "{}\t{}\t{}",
                if let Some(id) = channel.creator.clone() {
                    let uname = get_user_name_by_id(cfg, &id).await;
                    uname.green()
                } else {
                    "N/A".red()
                },
                channel.created.0.naive_local(),
                channel.name.clone().unwrap_or("".to_string()).blue()
            )
        }
    } else if remote.is_some() {
        let remote = remote.unwrap().to_path_buf();
        let channel_name = match &remote.strip_prefix("/") {
            Ok(path) => path.clone(),
            Err(_) => remote.as_path().clone(),
        };
        let req = SlackApiConversationsListRequest::new();
        let convos = session.conversations_list(&req).await?;
        for channel in &convos.channels {
            if channel.name.clone().unwrap_or("N/A".to_string())
                == channel_name.to_str().unwrap().to_string()
            {
                let cid = channel.id.clone();
                // println!("CID IS: {}", &cid);
                let req = SlackApiFilesListRequest::new().with_channel_id(cid);
                let files = session.files_list(&req).await;
                // println!("files: {:?}", &files);
                for file in files.unwrap().files {
                    let created = match file.created {
                        Some(created) => created.0.naive_local().to_string(),
                        None => "N/A".to_string(),
                    };
                    println!(
                        "{}\t{}\t{}:{}\t- {}",
                        if let Some(id) = file.user.clone() {
                            let uname = get_user_name_by_id(cfg, &id).await;
                            uname.green()
                        } else {
                            "N/A".red()
                        },
                        created,
                        file.name.clone().unwrap_or("".to_string()).blue(),
                        file.id.0,
                        file.url_private_download.unwrap().to_string()
                    )
                }
            }
        }

        //println!("Files in channel {}", channel_name.display());
    }

    Ok(())
}

async fn get_session(
    cfg: &SlackConfig,
) -> Result<
    //(
    //SlackClient<SlackClientHyperConnector<HttpsConnector<HttpConnector>>>,
    SlackClientSession<'static, SlackClientHyperConnector<HttpsConnector<HttpConnector>>>,
    //),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let client = Box::new(SlackClient::new(
        SlackClientHyperConnector::new()?, //.expect("Failed to get client!"),
    ));
    let client = Box::leak(client);
    let token_value: SlackApiTokenValue = cfg.bearer_token.clone().into();
    let token = Box::new(SlackApiToken::new(token_value.clone()));
    let token = Box::leak(token);
    let session = client.open_session(token);
    Ok(session)
}

async fn get_file(
    cfg: &SlackConfig,
    remote_id: &String,
    local: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let session = get_session(&cfg).await?;
    //println!("Getting INFO...");
    let req = SlackApiFilesInfoRequest::new(SlackFileId(remote_id.clone()));
    let file_info = session.files_info(&req).await?;
    //println!("Retrieving {:?}", &file_info);
    fetch_file(
        &cfg.bearer_token,
        &file_info.file.url_private_download.unwrap().to_string(),
        &file_info.file.name.unwrap(),
    )
    .await?;
    Ok(())
}

async fn fetch_file(
    token: &String,
    url: &String,
    file_name: &String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Fetchening {}!", url);
    let client = reqwest::Client::new();
    let response = client.get(url).bearer_auth(token.clone()).send().await?;
    // let response = reqwest::get(url).await?;
    let mut file = std::fs::File::create(file_name)?;
    let mut content = Cursor::new(response.bytes().await?);
    std::io::copy(&mut content, &mut file)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = SlackConfig::parse();
    // println!("CFG: {:?}", &cfg);

    match &cfg.command {
        Commands::Ls { remote } => {
            list_channels(&cfg, remote).await.unwrap();
        }
        Commands::Get { remote_id, local } => get_file(&cfg, remote_id, None).await?,
        Commands::Put { local, remote } => rest_file_upload(&cfg, local, remote).await?,
        _ => println!("Any other match..."),
        Commands::Put { local, remote } => {}
    }

    //rest_file_upload(&cfg).await?;
    Ok(())
}
