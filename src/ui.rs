use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        #[cfg(feature = "appimage")]
        let prefix = std::env::var("APPDIR").unwrap_or("".to_string());
        #[cfg(not(feature = "appimage"))]
        let prefix = "".to_string();
        #[cfg(feature = "flatpak")]
        let dir = "/app";
        #[cfg(not(feature = "flatpak"))]
        let dir = "/usr";
        sciter::set_library(&(prefix + dir + "/lib/rustdesk/libsciter-gtk.so")).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String) -> String {
        test_if_valid_server(host)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_rdp_service_open(&self) -> bool {
        is_rdp_service_open()
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(id)
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_rdp_service_open();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
