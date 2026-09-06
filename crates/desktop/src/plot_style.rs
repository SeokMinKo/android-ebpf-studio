/// Presentation settings are separate from the analysis and selection caches.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct PlotStyle {
    point_diameter: f32,
    colors: BTreeMap<String, BTreeMap<String, [u8; 3]>>,
}

impl Default for PlotStyle {
    fn default() -> Self {
        Self {
            point_diameter: 5.0,
            colors: BTreeMap::new(),
        }
    }
}

impl PlotStyle {
    fn normalize(&mut self) {
        self.point_diameter = if self.point_diameter.is_finite() {
            self.point_diameter.clamp(2.0, 20.0)
        } else {
            5.0
        };
    }

    fn custom_color(&self, category: GroupBy, name: &str) -> Option<[u8; 3]> {
        self.colors
            .get(&format!("{category:?}"))?
            .get(name)
            .copied()
    }

    fn set_color(&mut self, category: GroupBy, name: &str, color: [u8; 3]) {
        self.colors
            .entry(format!("{category:?}"))
            .or_default()
            .insert(name.to_owned(), color);
    }

    fn reset_color(&mut self, category: GroupBy, name: &str) {
        if let Some(colors) = self.colors.get_mut(&format!("{category:?}")) {
            colors.remove(name);
        }
    }

    fn color(&self, category: GroupBy, name: &str) -> Color32 {
        if let Some([r, g, b]) = self.custom_color(category, name) {
            return Color32::from_rgb(r, g, b);
        }
        match (category, name) {
            (GroupBy::Direction, "Read") => return accent(),
            (GroupBy::Direction, "Write") => return green(),
            (GroupBy::AccessPattern, "Sequential") | (GroupBy::Confidence, "Exact") => {
                return green();
            }
            (GroupBy::AccessPattern, "Random")
            | (GroupBy::Confidence, "Probable" | "Probable async") => return amber(),
            (_, "Unattributed" | "Unknown" | "Unresolved") => return muted(),
            (GroupBy::None, _) => return accent(),
            _ => {}
        }
        // Stable across runs and filters, unlike the position in a sorted group list.
        let hash = name.as_bytes().iter().fold(0x811c9dc5_u32, |hash, byte| {
            (hash ^ *byte as u32).wrapping_mul(0x01000193)
        });
        [
            accent(),
            green(),
            red(),
            amber(),
            muted(),
            ink(),
            Color32::from_rgb(175, 95, 225),
            Color32::from_rgb(200, 100, 35),
        ][hash as usize % 8]
    }
}

impl StudioApp {
    fn plot_colors_ui(&mut self, ui: &mut egui::Ui, names: &[String]) {
        let mut header = egui::CollapsingHeader::new("Colors · customize category colors");
        if self.render_qa.output.is_some()
            && std::env::var_os("ANDROID_EBPF_QA_PLOT_STYLE").is_some()
        {
            header = header.open(Some(true));
        }
        header.show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Click a color swatch to set RGB. Auto follows the theme.");
                if ui.button("Reset category colors").clicked() { self.plot_style.colors.remove(&format!("{:?}", self.group_by)); }
                if ui.button("Reset point size").clicked() { self.plot_style.point_diameter=5.0; }
            });
            if names.is_empty() { ui.label("Colors appear when this category has plotted data."); }
            egui::ScrollArea::vertical().id_salt("plot-color-list").max_height(110.0).show(ui, |ui| {
                for name in names {
                    ui.push_id((format!("{:?}", self.group_by), name), |ui| {
                        let color=self.plot_style.color(self.group_by, name);
                        let mut rgb=[color.r(),color.g(),color.b()];
                        ui.horizontal_wrapped(|ui| {
                            let response=ui.color_edit_button_srgb(&mut rgb);
                            if name=="Read" {self.render_qa.color_picker_button=Some(response.rect.center());}
                            if response.changed() { self.plot_style.set_color(self.group_by,name,rgb); }
                            ui.label(name);
                            ui.small(format!("#{:02X}{:02X}{:02X}",rgb[0],rgb[1],rgb[2]));
                            if self.plot_style.custom_color(self.group_by,name).is_some() {
                                ui.small("Custom");
                                if ui.small_button("Auto").clicked() { self.plot_style.reset_color(self.group_by,name); }
                            } else { ui.small("Auto"); }
                        });
                    });
                }
            });
            ui.small("Size is point diameter in logical pixels (scales with Windows DPI). Custom colors stay fixed across themes. Labels and selection outlines remain visible. Preferences are saved on normal exit.");
        });
    }
}

#[cfg(test)]
mod plot_style_tests {
    use super::*;

    #[test]
    fn normal_app_save_persists_size_colors_and_category() {
        #[derive(Default)]
        struct MemoryStorage(BTreeMap<String, String>);
        impl eframe::Storage for MemoryStorage {
            fn get_string(&self, key: &str) -> Option<String> {
                self.0.get(key).cloned()
            }
            fn set_string(&mut self, key: &str, value: String) {
                self.0.insert(key.into(), value);
            }
            fn remove_string(&mut self, key: &str) {
                self.0.remove(key);
            }
            fn flush(&mut self) {}
        }
        let mut app = StudioApp {
            group_by: GroupBy::File,
            ..Default::default()
        };
        app.plot_style.point_diameter = 13.5;
        app.plot_style
            .set_color(GroupBy::File, "/data/test.bin", [40, 90, 180]);
        let mut storage = MemoryStorage::default();
        eframe::App::save(&mut app, &mut storage);
        let style: PlotStyle = eframe::get_value(&storage, "plot-style-v1").unwrap();
        assert_eq!(style.point_diameter, 13.5);
        assert_eq!(
            style.custom_color(GroupBy::File, "/data/test.bin"),
            Some([40, 90, 180])
        );
        assert_eq!(
            eframe::get_value::<GroupBy>(&storage, "plot-color-category-v1"),
            Some(GroupBy::File)
        );
    }

    #[test]
    fn colors_stay_with_category_identity_across_filters_and_round_trip() {
        let mut style = PlotStyle::default();
        style.set_color(GroupBy::Direction, "Read", [220, 30, 180]);
        style.set_color(GroupBy::File, "Read", [30, 200, 50]);
        let file_before = style.color(GroupBy::File, "/data/a");
        let _ = style.color(GroupBy::File, "/data/another-group");
        assert_eq!(style.color(GroupBy::File, "/data/a"), file_before);
        style.point_diameter = 17.0;
        let mut restored: PlotStyle =
            serde_json::from_str(&serde_json::to_string(&style).unwrap()).unwrap();
        assert_eq!(restored.point_diameter, 17.0);
        assert_eq!(
            restored.color(GroupBy::Direction, "Read"),
            Color32::from_rgb(220, 30, 180)
        );
        assert_eq!(
            restored.color(GroupBy::File, "Read"),
            Color32::from_rgb(30, 200, 50)
        );
        restored.reset_color(GroupBy::Direction, "Read");
        assert_eq!(restored.color(GroupBy::Direction, "Read"), accent());
        assert_eq!(
            restored.custom_color(GroupBy::File, "Read"),
            Some([30, 200, 50])
        );
    }

    #[test]
    fn corrupt_sizes_are_bounded_and_write_does_not_inherit_reads_color_when_filtered() {
        let mut style = PlotStyle {
            point_diameter: f32::NAN,
            ..Default::default()
        };
        style.normalize();
        assert_eq!(style.point_diameter, 5.0);
        style.point_diameter = 10000.0;
        style.normalize();
        assert_eq!(style.point_diameter, 20.0);
        assert_eq!(style.color(GroupBy::Direction, "Write"), green());
        assert_ne!(
            style.color(GroupBy::Direction, "Write"),
            style.color(GroupBy::Direction, "Read")
        );
    }
}
