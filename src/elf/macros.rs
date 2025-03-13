#[macro_export]
macro_rules! read_le_int {
    ($ty:ident, $in:expr) => {{
        let (int_bytes, rest) = $in.split_at(std::mem::size_of::<$ty>());
        $in = rest;
        $ty::from_le_bytes(int_bytes.try_into()?)
    }};
}

#[macro_export]
macro_rules! read_be_int {
    ($ty:ident, $in:expr) => {{
        let (int_bytes, rest) = $in.split_at(std::mem::size_of::<$ty>());
        $in = rest;
        $ty::from_be_bytes(int_bytes.try_into()?)
    }};
}

#[macro_export]
macro_rules! impl_elfheader {
    ($desc:literal, pub struct $name:ident { $( $field:ident : $type:ident ),* $(,)? }) => {
        pub struct $name {
            $( $field : $type ),*
        }

        impl ElfHeader for $name {
            fn describe() -> &'static str {
                $desc
            }

            #[allow(unused_assignments)]
            fn from_le_bytes(buf: &[u8]) -> Result<Self, ReadErr> {
                let mut input = buf;

                Ok(Self {
                    $( $field: crate::read_le_int!($type, input) ),*
                })
            }

            #[allow(unused_assignments)]
            fn from_be_bytes(buf: &[u8]) -> Result<Self, ReadErr> {
                let mut input = buf;

                Ok(Self {
                    $( $field: crate::read_be_int!($type, input) ),*
                })
            }
        }
    }
}

#[macro_export]
macro_rules! field_getter {
    ($field:ident) => {
        fn $field(&self) -> u64 {
            self.$field.into()
        }
    };
}
