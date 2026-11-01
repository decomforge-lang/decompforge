//! Nucleo de DecompForge (Fase 1).
//!
//! * [`loader`]: deteccion de formato y arquitectura, mapa de secciones.
//! * [`analysis`]: desensamblado con Capstone y deteccion recursiva de
//!   funciones y llamadas.
//! * [`project`]: proyecto SQLite, importacion y exportacion JSON.
//! * [`synthetic`]: binarios sinteticos propios para pruebas y demos
//!   (nunca contenido de terceros; ver docs/ACCEPTABLE_USE.md).
//!
//! # Ejemplo
//!
//! Cargar, analizar y consultar un proyecto en memoria:
//!
//! ```
//! use decompforge_core::loader::{load, LoadOptions};
//! use decompforge_core::{synthetic, Arch, Project};
//!
//! let data = synthetic::elf_mips_le32_program();
//! let binary = load(&data, &LoadOptions::default())?;
//! assert_eq!(binary.arch, Arch::Mips);
//!
//! let mut project = Project::in_memory("demo", Some("ps2"))?;
//! project.import_binary(&data, &LoadOptions::default(), "humano")?;
//! let summary = project.analyze(&data, "humano")?;
//! assert_eq!(summary.functions, 3);
//! assert_eq!(summary.call_edges, 2);
//! # Ok::<(), decompforge_core::Error>(())
//! ```
//!
//! En disco, [`Project::create`] y [`Project::open`] sustituyen a
//! [`Project::in_memory`]. El `.dfproj` no guarda el binario: [`Project::analyze`]
//! exige el mismo SHA-256 que el archivo importado.

#![warn(missing_docs)]

pub mod analysis;
pub mod arch;
pub mod db;
pub mod error;
pub mod loader;
pub mod project;
pub mod synthetic;
mod timeutil;

pub use arch::{Arch, Endian, Format};
pub use error::{Error, Result};
pub use loader::{FlatSpec, LoadOptions, LoadedBinary, Section};
pub use project::{Project, ProjectInfo};
