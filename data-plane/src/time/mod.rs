use tokio::time::Duration;
use tokio::time;
use libc::{clock_gettime, clock_settime, timespec, CLOCK_REALTIME, CLOCK_MONOTONIC_RAW};
use std::io::Error;
use std::time::UNIX_EPOCH;
use std::time::SystemTime;

pub struct TimeSync;

impl TimeSync {

    pub async fn run(interval_duration: Duration) {
        let mut interval = time::interval(interval_duration);
        loop {
            interval.tick().await;
            println!("This code runs every 5 seconds");
            Self::sync_time_from_host();
            Self::get_time();
        }
    }

    // fn sync_time_from_host() -> Result<(), String> {
    //     let new_time: Duration = Duration::new(0, 0);
    //     let timespec = timespec {
    //         tv_sec: new_time.as_secs() as i64,
    //         tv_nsec: new_time.subsec_nanos() as i64,
    //     };
 
    //     // let timespec = timespec {
    //     //     tv_sec: 0,
    //     //     tv_nsec: 0,
    //     // };
    
    //     let result = unsafe { clock_settime(CLOCK_MONOTONIC_RAW, &timespec) };
    //     if result == 0 {
    //         Ok(())
    //     } else {
    //         println!("THE ERRRRR {:?}", Error::last_os_error());
    //         Err("Failed to set system time".into())
    //     }
    // }


fn sync_time_from_host() {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    let ts = timespec {
        tv_sec: time.as_secs() as i64,
        tv_nsec: time.subsec_millis() as i64,  
    };

    let result = unsafe {
        clock_settime(CLOCK_REALTIME, &ts as *const timespec)
    };

    if result == 0 {
        println!("SET TIME SUCCESSFULLY!!!");
    } else {
        println!("THE ERRRRR {:?}", Error::last_os_error());
    }
}

    fn get_time() {
        let mut ts = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
    
        unsafe {
            if libc::clock_gettime(CLOCK_REALTIME, &mut ts) != 0 {
                println!("Failed to get time");
            }
        }

        println!("DURATION!!!!! {:?}", ts);
    }

}