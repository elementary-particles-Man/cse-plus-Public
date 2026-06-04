use zeroize::Zeroize;

pub struct TuffKeyBundle {
    pub component_a: [u8; 32],
    pub component_b: [u8; 32],
    pub component_c: [u8; 32],
}

impl Drop for TuffKeyBundle {
    fn drop(&mut self) {
        self.component_a.zeroize();
        self.component_b.zeroize();
        self.component_c.zeroize();
    }
}

impl TuffKeyBundle {
    pub fn from_components(
        component_a: &[u8; 32],
        component_b: &[u8; 32],
        component_c: &[u8; 32],
    ) -> Self {
        Self {
            component_a: *component_a,
            component_b: *component_b,
            component_c: *component_c,
        }
    }
}
