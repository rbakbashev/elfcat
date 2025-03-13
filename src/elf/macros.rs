#[macro_export]
macro_rules! field_getter {
    ($field:ident) => {
        fn $field(&self) -> u64 {
            self.$field.into()
        }
    };
}
