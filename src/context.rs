use crate::session::builder::SessionBuilder;
use crate::session::builder::SessionBuilderError;
use crate::util::get_last_error_info;
use crate::Session;
use crate::{ContextError, SolClientReturnCode, SolaceLogLevel};
use solace_rs_sys as ffi;
use std::mem;
use std::ptr;
use std::sync::Mutex;
use std::sync::OnceLock;
use tracing::warn;

use crate::message::InboundMessage;
use crate::session::SessionEvent;
use std::sync::Arc;
type Result<T> = std::result::Result<T, ContextError>;

pub(super) struct RawContext {
    // This pointer must never be allowed to leave the struct
    pub(crate) ctx: ffi::solClient_opaqueContext_pt,
}

static SOLACE_GLOBAL_INIT: OnceLock<i32> = OnceLock::new();

impl RawContext {
    /// Create a Solace context.
    ///
    /// # Safety
    /// Context initializes global variables so it is not safe to have multiple solace contexts.
    pub unsafe fn new(log_level: SolaceLogLevel) -> Result<Self> {
        Self::new_with_thread(log_level, true)
    }

    /// Create a Solace context, optionally without a context thread.
    ///
    /// When `create_thread = false` the application must drive event processing
    /// by calling [`RawContext::process_events`] from its own loop.
    ///
    /// # Safety
    /// Context initializes global variables so it is not safe to have multiple solace contexts.
    pub unsafe fn new_with_thread(log_level: SolaceLogLevel, create_thread: bool) -> Result<Self> {
        let rc = SOLACE_GLOBAL_INIT
            .get_or_init(|| ffi::solClient_initialize(log_level as u32, ptr::null_mut()));

        let rc = SolClientReturnCode::from_raw(*rc);

        if !rc.is_ok() {
            let subcode = get_last_error_info();
            return Err(ContextError::InitializationFailed(rc, subcode));
        }
        let mut ctx: ffi::solClient_opaqueContext_pt = ptr::null_mut();
        let mut context_func: ffi::solClient_context_createFuncInfo_t =
            ffi::solClient_context_createFuncInfo {
                regFdInfo: ffi::solClient_context_createRegisterFdFuncInfo {
                    regFdFunc_p: None,
                    unregFdFunc_p: None,
                    user_p: ptr::null_mut(),
                },
            };

        let thread_val = if create_thread {
            solace_rs_sys::SOLCLIENT_PROP_ENABLE_VAL.as_ptr() as *const i8
        } else {
            solace_rs_sys::SOLCLIENT_PROP_DISABLE_VAL.as_ptr() as *const i8
        };

        let mut context_props: [*const i8; 3] = [
            solace_rs_sys::SOLCLIENT_CONTEXT_PROP_CREATE_THREAD.as_ptr() as *const i8,
            thread_val,
            ptr::null(),
        ];

        let solace_context_raw_rc = unsafe {
            ffi::solClient_context_create(
                context_props.as_mut_ptr(),
                &mut ctx,
                &mut context_func,
                mem::size_of::<ffi::solClient_context_createRegisterFdFuncInfo>(),
            )
        };

        let rc = SolClientReturnCode::from_raw(solace_context_raw_rc);

        if !rc.is_ok() {
            let subcode = get_last_error_info();
            return Err(ContextError::InitializationFailed(rc, subcode));
        }
        Ok(Self { ctx })
    }

    /// Drive Solace event processing for poll-mode contexts.
    ///
    /// Returns `true` if an event was processed, `false` if no events were pending.
    pub fn process_events(&mut self) -> bool {
        let rc = unsafe { ffi::solClient_context_processEvents(self.ctx) };
        let rc = SolClientReturnCode::from_raw(rc);
        // SOLCLIENT_OK = event processed; SOLCLIENT_NOT_READY = no event
        rc.is_ok()
    }
}

impl Drop for RawContext {
    fn drop(&mut self) {
        let return_code = unsafe { ffi::solClient_context_destroy(&mut self.ctx) };
        if return_code != ffi::solClient_returnCode_SOLCLIENT_OK {
            warn!("Solace context did not drop properly");
        }
    }
}

unsafe impl Send for RawContext {}

/// Handle for a Solace context, used to create sessions.
///
/// It is thread safe, and can be safely cloned and shared. Each clone
/// references the same underlying C context. Internally, an `Arc` is
/// used to implement this in a threadsafe way.
///
/// Also note that this binding deviates from the C API in that each
/// session created from a context initially owns a clone of that
/// context.
///
///
#[derive(Clone)]
pub struct Context {
    pub(super) raw: Arc<Mutex<RawContext>>,
}

impl Context {
    /// Create a threaded Solace context (Solace manages its own event thread).
    pub fn new(log_level: SolaceLogLevel) -> std::result::Result<Self, ContextError> {
        Ok(Self {
            raw: Arc::new(Mutex::new(unsafe { RawContext::new(log_level) }?)),
        })
    }

    /// Create a poll-mode Solace context (no internal context thread).
    ///
    /// The caller must drive event processing by calling [`Context::process_events`]
    /// from its own loop. This is used when a dedicated engine thread polls Solace
    /// at a controlled rate (e.g., Phase C/E engine modes).
    pub fn new_poll_mode(log_level: SolaceLogLevel) -> std::result::Result<Self, ContextError> {
        Ok(Self {
            raw: Arc::new(Mutex::new(unsafe {
                RawContext::new_with_thread(log_level, false)
            }?)),
        })
    }

    /// Drive Solace event processing (poll-mode only).
    ///
    /// Returns `true` if an event was processed, `false` if no events were pending.
    /// Must be called repeatedly from the application's poll loop when created via
    /// [`Context::new_poll_mode`].
    pub fn process_events(&self) -> bool {
        self.raw.lock().expect("context lock").process_events()
    }

    pub fn session_builder<Host, Vpn, Username, Password, OnMessage, OnEvent>(
        &self,
    ) -> SessionBuilder<Host, Vpn, Username, Password, OnMessage, OnEvent> {
        SessionBuilder::new(self.clone())
    }

    pub fn session<'session, Host, Vpn, Username, Password, OnMessage, OnEvent>(
        &self,
        host_name: Host,
        vpn_name: Vpn,
        username: Username,
        password: Password,
        on_message: Option<OnMessage>,
        on_event: Option<OnEvent>,
    ) -> std::result::Result<Session<'session, OnMessage, OnEvent>, SessionBuilderError>
    where
        Host: Into<Vec<u8>>,
        Vpn: Into<Vec<u8>>,
        Username: Into<Vec<u8>>,
        Password: Into<Vec<u8>>,
        OnMessage: FnMut(InboundMessage) + Send + 'session,
        OnEvent: FnMut(SessionEvent) + Send + 'session,
    {
        let mut builder = SessionBuilder::new(self.clone())
            .host_name(host_name)
            .vpn_name(vpn_name)
            .username(username)
            .password(password);

        if let Some(on_message) = on_message {
            builder = builder.on_message(on_message);
        }

        if let Some(on_event) = on_event {
            builder = builder.on_event(on_event);
        }

        builder.build()
    }
}
