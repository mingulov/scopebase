use scopebase_capture::quantity::{Count, Events, Records};
fn main() {
    let events = Count::<Events>::new(2);
    let records = Count::<Events>::new(3);
    let _ = events.checked_add(records);
}
