use chrono::{DateTime, Local, TimeDelta};

pub fn get_fmt_time(fmt:&str) -> String{

    let now: DateTime<Local> = Local::now();
    let dft = now.format(fmt);

    dft.to_string()
}

pub fn get_fmt_duration(seconds:i64, mut format_str:String) -> String {


    let duration = TimeDelta::try_seconds(seconds).unwrap();

    let days = duration.num_days();
    let hours = duration.num_hours() % 24;
    let minutes = duration.num_minutes() % 60;
    let seconds = duration.num_seconds() % 60;

    format_str = format_str.replace("{d}", &days.to_string());
    format_str = format_str.replace("{h}", &hours.to_string());
    format_str = format_str.replace("{m}", &minutes.to_string());
    format_str = format_str.replace("{s}", &seconds.to_string());

    format_str
}