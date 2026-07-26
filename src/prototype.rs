use std::ffi::CString;
use std::ptr;

use revng_sys::{
    rp_error, rp_manager, rp_manager_add_struct_field, rp_manager_create_struct_type,
    rp_primitive_kind, rp_primitive_type, rp_type, rp_type_kind,
};

use crate::error::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimitiveKind {
    Float,
    Generic,
    Number,
    PointerOrNumber,
    Signed,
    Unsigned,
    Void,
}

impl PrimitiveKind {
    fn to_ffi(self) -> rp_primitive_kind {
        match self {
            Self::Float => rp_primitive_kind::RP_PRIMITIVE_KIND_FLOAT,
            Self::Generic => rp_primitive_kind::RP_PRIMITIVE_KIND_GENERIC,
            Self::Number => rp_primitive_kind::RP_PRIMITIVE_KIND_NUMBER,
            Self::PointerOrNumber => rp_primitive_kind::RP_PRIMITIVE_KIND_POINTER_OR_NUMBER,
            Self::Signed => rp_primitive_kind::RP_PRIMITIVE_KIND_SIGNED,
            Self::Unsigned => rp_primitive_kind::RP_PRIMITIVE_KIND_UNSIGNED,
            Self::Void => rp_primitive_kind::RP_PRIMITIVE_KIND_VOID,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Primitive {
    kind: PrimitiveKind,
    size: u16,
}

impl Primitive {
    pub fn new(kind: PrimitiveKind, size: u16) -> Self {
        Self { kind, size }
    }

    pub fn signed(size: u16) -> Self {
        Self::new(PrimitiveKind::Signed, size)
    }

    pub fn unsigned(size: u16) -> Self {
        Self::new(PrimitiveKind::Unsigned, size)
    }

    pub fn float(size: u16) -> Self {
        Self::new(PrimitiveKind::Float, size)
    }

    pub fn generic(size: u16) -> Self {
        Self::new(PrimitiveKind::Generic, size)
    }

    pub fn void() -> Self {
        Self::new(PrimitiveKind::Void, 0)
    }

    pub(crate) fn to_ffi(self) -> rp_primitive_type {
        rp_primitive_type {
            kind: self.kind.to_ffi(),
            size: u64::from(self.size),
        }
    }

    fn to_type_ffi(self) -> rp_type {
        rp_type {
            kind: rp_type_kind::RP_TYPE_KIND_PRIMITIVE,
            is_const: false,
            primitive: self.to_ffi(),
            size: 0,
            definition_id: 0,
            element_type: ptr::null(),
        }
    }
}

struct Field {
    offset: u64,
    name: String,
    ty: Type,
}

pub struct Struct {
    name: String,
    size: u64,
    fields: Vec<Field>,
}

impl Struct {
    pub fn new(name: impl Into<String>, size: u64) -> Self {
        Self {
            name: name.into(),
            size,
            fields: Vec::new(),
        }
    }

    pub fn with_field(mut self, offset: u64, name: impl Into<String>, ty: impl Into<Type>) -> Self {
        self.fields.push(Field {
            offset,
            name: name.into(),
            ty: ty.into(),
        });
        self
    }

    unsafe fn create(
        &self,
        manager: *mut rp_manager,
        pointer_size: u64,
        error: *mut rp_error,
    ) -> Result<u64, Error> {
        let name = CString::new(self.name.as_str()).expect("struct name has no NUL");
        let definition = unsafe {
            rp_manager_create_struct_type(manager, name.as_ptr(), ptr::null(), self.size, 0, error)
        };
        if definition == u64::MAX {
            return Err(Error::pipeline(format!(
                "failed to create the struct type '{}'",
                self.name
            )));
        }
        for field in &self.fields {
            let field_name = CString::new(field.name.as_str()).expect("field name has no NUL");
            let field_type = unsafe { field.ty.materialise(manager, pointer_size, error)? };
            let added = unsafe {
                rp_manager_add_struct_field(
                    manager,
                    definition,
                    field.offset,
                    field_name.as_ptr(),
                    ptr::null(),
                    &field_type.ffi(),
                    error,
                )
            };
            if !added {
                return Err(Error::pipeline(format!(
                    "failed to add field '{}' to struct '{}'",
                    field.name, self.name
                )));
            }
        }
        Ok(definition)
    }
}

pub enum Type {
    Pointer(Box<Type>),
    Primitive(Primitive),
    Struct(Struct),
}

pub(crate) struct Materialised {
    ty: rp_type,
    // SAFETY: `ty.element_type` is a raw pointer into `pointee.ty`, so the whole
    // tree must stay alive for as long as `ty` is used across FFI.
    #[allow(dead_code)]
    pointee: Option<Box<Materialised>>,
}

impl Materialised {
    pub(crate) fn ffi(&self) -> rp_type {
        self.ty
    }
}

impl Type {
    pub fn pointer(target: impl Into<Type>) -> Self {
        Self::Pointer(Box::new(target.into()))
    }

    pub(crate) unsafe fn materialise(
        &self,
        manager: *mut rp_manager,
        pointer_size: u64,
        error: *mut rp_error,
    ) -> Result<Materialised, Error> {
        match self {
            Self::Primitive(primitive) => Ok(Materialised {
                ty: primitive.to_type_ffi(),
                pointee: None,
            }),
            Self::Struct(structure) => {
                let definition = unsafe { structure.create(manager, pointer_size, error)? };
                Ok(Materialised {
                    ty: rp_type {
                        kind: rp_type_kind::RP_TYPE_KIND_DEFINED,
                        is_const: false,
                        primitive: Primitive::void().to_ffi(),
                        size: 0,
                        definition_id: definition,
                        element_type: ptr::null(),
                    },
                    pointee: None,
                })
            }
            Self::Pointer(target) => {
                let pointee =
                    Box::new(unsafe { target.materialise(manager, pointer_size, error)? });
                let element_type = ptr::from_ref(&pointee.ty);
                Ok(Materialised {
                    ty: rp_type {
                        kind: rp_type_kind::RP_TYPE_KIND_POINTER,
                        is_const: false,
                        primitive: Primitive::void().to_ffi(),
                        size: pointer_size,
                        definition_id: 0,
                        element_type,
                    },
                    pointee: Some(pointee),
                })
            }
        }
    }
}

impl From<Primitive> for Type {
    fn from(primitive: Primitive) -> Self {
        Self::Primitive(primitive)
    }
}

impl From<Struct> for Type {
    fn from(structure: Struct) -> Self {
        Self::Struct(structure)
    }
}

pub struct Prototype {
    arguments: Vec<Type>,
    returns: Type,
}

impl Prototype {
    pub fn returning(returns: impl Into<Type>) -> Self {
        Self {
            arguments: Vec::new(),
            returns: returns.into(),
        }
    }

    pub fn with_argument(mut self, argument: impl Into<Type>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    pub(crate) fn arguments(&self) -> &[Type] {
        &self.arguments
    }

    pub(crate) fn returns(&self) -> &Type {
        &self.returns
    }

    pub(crate) fn as_primitives(&self) -> Option<(Vec<Primitive>, Primitive)> {
        let arguments = self
            .arguments
            .iter()
            .map(|argument| match argument {
                Type::Primitive(primitive) => Some(*primitive),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        let Type::Primitive(returns) = &self.returns else {
            return None;
        };
        Some((arguments, *returns))
    }
}
