// Storage capacity defines the initial address viewport, never the retained cohort.
#[derive(Default)]
struct StorageRange {
    detected_bytes: Option<u64>,
    override_bytes: Option<u64>,
}

fn phone_storage_bytes(partitions: &str) -> Option<u64> {
    // Do not sum partitions, device-mapper aliases, RAM disks or boot LUNs.
    let bytes = partitions.lines().filter_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 4 || !matches!(fields[3], "sda" | "mmcblk0" | "nvme0n1") { return None; }
        fields[2].parse::<u64>().ok()?.checked_mul(1024)
    }).max().filter(|v| *v >= 16_000_000_000)?;
    // Physical user-LUN capacity can be slightly below/above the marketed size.
    // Outside a recognized capacity class, retain the measured byte size.
    Some([32,64,128,256,512,1000,2000,4000].into_iter().map(|gb|gb*1_000_000_000u64)
        .find(|nominal| (bytes as f64) >= *nominal as f64 * 0.85 && (bytes as f64) <= *nominal as f64 * 1.05)
        .unwrap_or(bytes))
}

impl StorageRange {
    fn from_session(path: &std::path::Path) -> Self {
        let detected_bytes = path.parent().and_then(|parent| std::fs::read(parent.join("device-profile.json")).ok())
            .and_then(|data|serde_json::from_slice::<serde_json::Value>(&data).ok())
            .and_then(|profile|profile.get("block_devices").and_then(|v|v.as_str()).and_then(phone_storage_bytes));
        Self {detected_bytes,override_bytes:None}
    }
    fn bytes(&self) -> Option<u64> { self.override_bytes.or(self.detected_bytes) }
    fn y_max(&self, axis: AxisMetric) -> Option<f64> {
        let divisor=match axis {AxisMetric::AddressMB=>1_000_000.,AxisMetric::AddressKiB=>1024.,AxisMetric::Sector=>512.,_=>return None};
        self.bytes().map(|bytes|bytes as f64/divisor)
    }
}

impl StudioApp {
    fn storage_range_ui(&mut self, ui: &mut egui::Ui) {
        if self.explorer_preset != ExplorerPreset::LbaDistribution { return; }
        let previous=self.storage_range.override_bytes;
        ui.horizontal_wrapped(|ui| {
            ui.label("Storage size / default Y range");
            let auto=self.storage_range.detected_bytes.map_or("Auto: unknown".into(),|v|format!("Auto: {} GB",v as f64/1e9));
            egui::ComboBox::from_id_salt("lba-storage-size").selected_text(self.storage_range.override_bytes.map_or(auto.clone(),|v|format!("{} GB",v/1_000_000_000))).show_ui(ui,|ui| {
                ui.selectable_value(&mut self.storage_range.override_bytes,None,auto);
                for gb in [128,256,512,1000] {
                    ui.selectable_value(&mut self.storage_range.override_bytes,Some(gb*1_000_000_000),if gb==1000 {"1 TB".into()}else{format!("{gb} GB")});
                }
            });
            if ui.add_enabled(self.storage_range.bytes().is_some(),egui::Button::new("Reset to storage size")).clicked() { self.selection.fit_axis_ranges(); }
        });
        if previous!=self.storage_range.override_bytes {self.selection.fit_axis_ranges();}
        if self.storage_range.bytes().is_none() {ui.small("Storage capacity is absent from this session. Choose the phone capacity above; Auto fits the observed data until capacity is known.");}
        else {ui.small("Capacity sets the default viewport only. Out-of-range I/O remains in the analysis, tables and exports.");}
    }
}

#[cfg(test)]
mod storage_range_tests {
    use super::*;
    #[test]
    fn detects_phone_capacity_without_summing_aliases_or_partitions() {
        assert_eq!(phone_storage_bytes("8 0 497508352 sda\n8 15 470864956 sda15\n254 36 470864956 dm-36\n252 0 12582912 zram0"),Some(512_000_000_000));
        for gb in [128,256,512,1000] {
            let raw=format!("179 0 {} mmcblk0\n",gb*1_000_000_000u64/1024);
            assert_eq!(phone_storage_bytes(&raw),Some(gb*1_000_000_000));
        }
        assert_eq!(phone_storage_bytes("254 0 999999999999 dm-0\n8 1 999999999999 sda1\n"),None);
    }
    #[test]
    fn capacity_units_and_missing_profile_are_explicit() {
        let range=StorageRange {detected_bytes:Some(512_000_000_000),..Default::default()};
        assert_eq!(range.y_max(AxisMetric::AddressMB),Some(512000.));
        assert_eq!(range.y_max(AxisMetric::Sector),Some(1_000_000_000.));
        assert_eq!(range.y_max(AxisMetric::TimeMs),None);
        assert_eq!(StorageRange::default().y_max(AxisMetric::AddressMB),None);
    }
    #[test]
    fn offline_session_uses_its_own_profile() {
        let directory=std::env::temp_dir().join(format!("storage-profile-{}",uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path=directory.join("capture.ndjson");
        assert!(StorageRange::from_session(&path).bytes().is_none());
        std::fs::write(directory.join("device-profile.json"),r#"{"block_devices":"8 0 497508352 sda"}"#).unwrap();
        assert_eq!(StorageRange::from_session(&path).bytes(),Some(512_000_000_000));
        std::fs::remove_file(directory.join("device-profile.json")).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
