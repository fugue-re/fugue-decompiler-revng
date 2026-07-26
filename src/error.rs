use fugue_core::loader::LoaderError;
use fugue_core::storage::segments::SegmentStorageError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to build the segment address space")]
    AddressSpace(#[from] SegmentStorageError),
    #[error("failed to load the binary")]
    Loader(#[from] LoaderError),
    #[error("revng pipeline error: {message}")]
    Pipeline { message: String },
    #[error("unsupported architecture: {0}")]
    UnsupportedArchitecture(String),
}

impl Error {
    pub(crate) fn pipeline(message: impl Into<String>) -> Self {
        Self::Pipeline {
            message: message.into(),
        }
    }

    pub(crate) fn unsupported_architecture(name: impl Into<String>) -> Self {
        Self::UnsupportedArchitecture(name.into())
    }
}
