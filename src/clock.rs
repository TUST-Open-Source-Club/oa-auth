//! 时钟抽象：业务代码禁止直接调用 `Utc::now()`，统一通过 `Clock` 注入，保证测试可确定。

use chrono::{DateTime, Utc};

/// 可注入的时钟。
pub trait Clock: Send + Sync {
    /// 当前 UTC 时间。
    fn now(&self) -> DateTime<Utc>;
}

/// 系统时钟（生产环境使用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// 固定时钟（测试使用）：返回创建时指定的时间。
#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    /// 固定的当前时间。
    pub at: DateTime<Utc>,
}

impl FixedClock {
    /// 用指定时间构造固定时钟。
    pub fn new(at: DateTime<Utc>) -> Self {
        Self { at }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn fixed_clock_returns_fixed_time() {
        let at = Utc.with_ymd_and_hms(2026, 9, 13, 10, 0, 0).unwrap();
        let clock = FixedClock::new(at);
        assert_eq!(clock.now(), at);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(clock.now(), at, "固定时钟不应随时间变化");
    }

    #[test]
    fn system_clock_moves_forward() {
        let clock = SystemClock;
        let first = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(clock.now() >= first);
    }
}
