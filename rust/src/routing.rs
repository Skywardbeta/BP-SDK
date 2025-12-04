use crate::{
    error::{BpError, BpResult},
    types::{Bundle, Contact, Eid, Route},
};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

pub trait RoutingEngine: Send + Sync {
    fn name(&self) -> &str;
    fn compute_routes(&self, dest_eid: &Eid, contacts: &[Contact]) -> Vec<Route>;
    fn update_contact(&self, contact: Contact);
    fn should_forward(&self, bundle: &Bundle, contact: &Contact) -> bool;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingContext {
    pub bundle_id: Uuid,
    pub encounters: HashSet<Eid>,
    pub copies_left: u32,
    pub last_updated: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

impl RoutingContext {
    pub fn new(bundle_id: Uuid) -> Self {
        Self {
            bundle_id,
            encounters: HashSet::new(),
            copies_left: 1,
            last_updated: Utc::now(),
            metadata: HashMap::new(),
        }
    }
}

pub struct EpidemicRouting {
    name: String,
    contacts: RwLock<Vec<Contact>>,
    routing_history: RwLock<HashMap<Uuid, RoutingContext>>,
}

impl EpidemicRouting {
    pub fn new() -> Self {
        Self {
            name: "epidemic".to_string(),
            contacts: RwLock::new(Vec::new()),
            routing_history: RwLock::new(HashMap::new()),
        }
    }

    fn should_replicate(&self, bundle: &Bundle, contact: &Contact) -> bool {
        let history = self.routing_history.read();
        if let Some(context) = history.get(&bundle.id) {
            !context.encounters.contains(&contact.neighbor_eid)
        } else {
            true
        }
    }

    fn update_encounter(&self, bundle_id: Uuid, neighbor_eid: Eid) {
        let mut history = self.routing_history.write();
        let context = history.entry(bundle_id).or_insert_with(|| RoutingContext::new(bundle_id));
        context.encounters.insert(neighbor_eid);
        context.last_updated = Utc::now();
    }
}

impl RoutingEngine for EpidemicRouting {
    fn name(&self) -> &str {
        &self.name
    }

    fn compute_routes(&self, dest_eid: &Eid, contacts: &[Contact]) -> Vec<Route> {
        let mut routes = Vec::new();
        let current_time = Utc::now();

        for contact in contacts {
            if contact.is_active() && current_time >= contact.start_time {
                let route = Route::new(dest_eid.clone(), contact.neighbor_eid.clone(), 1)
                    .with_confidence(contact.confidence)
                    .with_validity(contact.end_time);
                routes.push(route);
            }
        }

        if routes.is_empty() {
            routes.push(Route::new(dest_eid.clone(), dest_eid.clone(), 100));
        }

        routes
    }

    fn update_contact(&self, contact: Contact) {
        let mut contacts = self.contacts.write();
        if let Some(existing) = contacts.iter_mut().find(|c| c.neighbor_eid == contact.neighbor_eid) {
            *existing = contact;
        } else {
            contacts.push(contact);
        }
    }

    fn should_forward(&self, bundle: &Bundle, contact: &Contact) -> bool {
        if bundle.dest_eid == contact.neighbor_eid {
            return true;
        }

        let should_replicate = self.should_replicate(bundle, contact);
        if should_replicate {
            self.update_encounter(bundle.id, contact.neighbor_eid.clone());
        }
        
        should_replicate
    }
}

impl Default for EpidemicRouting {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SprayAndWaitRouting {
    name: String,
    initial_copies: u32,
    contacts: RwLock<Vec<Contact>>,
    routing_history: RwLock<HashMap<Uuid, RoutingContext>>,
}

impl SprayAndWaitRouting {
    pub fn new(initial_copies: u32) -> Self {
        Self {
            name: "spray_and_wait".to_string(),
            initial_copies,
            contacts: RwLock::new(Vec::new()),
            routing_history: RwLock::new(HashMap::new()),
        }
    }

    fn initialize_context(&self, bundle_id: Uuid) -> RoutingContext {
        let mut context = RoutingContext::new(bundle_id);
        context.copies_left = self.initial_copies;
        context
    }

    fn should_spray(&self, bundle: &Bundle, contact: &Contact) -> bool {
        let mut history = self.routing_history.write();
        let context = history.entry(bundle.id)
            .or_insert_with(|| self.initialize_context(bundle.id));

        if bundle.dest_eid == contact.neighbor_eid {
            return true;
        }

        if context.copies_left > 1 && !context.encounters.contains(&contact.neighbor_eid) {
            context.copies_left -= 1;
            context.encounters.insert(contact.neighbor_eid.clone());
            context.last_updated = Utc::now();
            true
        } else {
            false
        }
    }
}

impl RoutingEngine for SprayAndWaitRouting {
    fn name(&self) -> &str {
        &self.name
    }

    fn compute_routes(&self, dest_eid: &Eid, contacts: &[Contact]) -> Vec<Route> {
        let mut routes = Vec::new();
        let current_time = Utc::now();

        for contact in contacts {
            if contact.is_active() && current_time >= contact.start_time {
                let cost = if contact.neighbor_eid == *dest_eid { 1 } else { 50 };
                let route = Route::new(dest_eid.clone(), contact.neighbor_eid.clone(), cost)
                    .with_confidence(contact.confidence)
                    .with_validity(contact.end_time);
                routes.push(route);
            }
        }

        routes.sort_by_key(|r| r.cost);
        routes
    }

    fn update_contact(&self, contact: Contact) {
        let mut contacts = self.contacts.write();
        if let Some(existing) = contacts.iter_mut().find(|c| c.neighbor_eid == contact.neighbor_eid) {
            *existing = contact;
        } else {
            contacts.push(contact);
        }
    }

    fn should_forward(&self, bundle: &Bundle, contact: &Contact) -> bool {
        self.should_spray(bundle, contact)
    }
}

pub struct ProphetRouting {
    name: String,
    alpha: f64,
    beta: f64,
    gamma: f64,
    delivery_probabilities: RwLock<HashMap<Eid, f64>>,
    contacts: RwLock<Vec<Contact>>,
    last_encounter: RwLock<HashMap<Eid, DateTime<Utc>>>,
}

impl ProphetRouting {
    pub fn new() -> Self {
        Self {
            name: "prophet".to_string(),
            alpha: 0.75,
            beta: 0.25,
            gamma: 0.98,
            delivery_probabilities: RwLock::new(HashMap::new()),
            contacts: RwLock::new(Vec::new()),
            last_encounter: RwLock::new(HashMap::new()),
        }
    }

    fn update_delivery_probability(&self, neighbor_eid: &Eid) {
        let mut probabilities = self.delivery_probabilities.write();
        let current_prob = probabilities.get(neighbor_eid).cloned().unwrap_or(0.0);
        let new_prob = current_prob + (1.0 - current_prob) * self.alpha;
        probabilities.insert(neighbor_eid.clone(), new_prob);
        
        let mut last_encounter = self.last_encounter.write();
        last_encounter.insert(neighbor_eid.clone(), Utc::now());
    }

    fn age_probabilities(&self) {
        let mut probabilities = self.delivery_probabilities.write();
        let last_encounter = self.last_encounter.read();
        let now = Utc::now();

        for (eid, prob) in probabilities.iter_mut() {
            if let Some(last_time) = last_encounter.get(eid) {
                let time_diff = now.signed_duration_since(*last_time).num_seconds() as f64;
                *prob *= self.gamma.powf(time_diff / 3600.0);
            }
        }
    }

    fn get_delivery_probability(&self, dest_eid: &Eid) -> f64 {
        self.age_probabilities();
        self.delivery_probabilities.read().get(dest_eid).cloned().unwrap_or(0.0)
    }
}

impl RoutingEngine for ProphetRouting {
    fn name(&self) -> &str {
        &self.name
    }

    fn compute_routes(&self, dest_eid: &Eid, contacts: &[Contact]) -> Vec<Route> {
        let mut routes = Vec::new();
        
        for contact in contacts {
            if contact.is_active() {
                let delivery_prob = self.get_delivery_probability(&contact.neighbor_eid);
                let cost = if delivery_prob > 0.0 {
                    (1.0 / delivery_prob) as u32
                } else {
                    1000
                };
                
                let route = Route::new(dest_eid.clone(), contact.neighbor_eid.clone(), cost)
                    .with_confidence(delivery_prob as f32)
                    .with_validity(contact.end_time);
                routes.push(route);
            }
        }

        routes.sort_by_key(|r| r.cost);
        routes
    }

    fn update_contact(&self, contact: Contact) {
        let neighbor_eid = contact.neighbor_eid.clone();
        
        let mut contacts = self.contacts.write();
        if let Some(existing) = contacts.iter_mut().find(|c| c.neighbor_eid == neighbor_eid) {
            *existing = contact;
        } else {
            contacts.push(contact);
        }
        
        self.update_delivery_probability(&neighbor_eid);
    }

    fn should_forward(&self, bundle: &Bundle, contact: &Contact) -> bool {
        if bundle.dest_eid == contact.neighbor_eid {
            return true;
        }

        let my_prob = self.get_delivery_probability(&bundle.dest_eid);
        let neighbor_prob = self.get_delivery_probability(&contact.neighbor_eid);
        
        neighbor_prob > my_prob + self.beta
    }
}

impl Default for ProphetRouting {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RoutingManager {
    engines: RwLock<HashMap<String, Arc<dyn RoutingEngine>>>,
    active_engine: RwLock<Option<String>>,
}

impl RoutingManager {
    pub fn new() -> Self {
        let manager = Self {
            engines: RwLock::new(HashMap::new()),
            active_engine: RwLock::new(None),
        };
        
        manager.register_engine(Arc::new(EpidemicRouting::new()));
        manager.register_engine(Arc::new(SprayAndWaitRouting::new(10)));
        manager.register_engine(Arc::new(ProphetRouting::new()));
        
        manager
    }

    pub fn register_engine(&self, engine: Arc<dyn RoutingEngine>) {
        let mut engines = self.engines.write();
        let name = engine.name().to_string();
        engines.insert(name.clone(), engine);
        
        if self.active_engine.read().is_none() {
            *self.active_engine.write() = Some(name);
        }
    }

    pub fn set_active_engine(&self, name: &str) -> BpResult<()> {
        let engines = self.engines.read();
        if engines.contains_key(name) {
            *self.active_engine.write() = Some(name.to_string());
            Ok(())
        } else {
            Err(BpError::NotFound)
        }
    }

    pub fn get_active_engine(&self) -> Option<Arc<dyn RoutingEngine>> {
        let active_name = self.active_engine.read().as_ref().cloned()?;
        self.engines.read().get(&active_name).cloned()
    }

    pub fn compute_routes(&self, dest_eid: &Eid, contacts: &[Contact]) -> Vec<Route> {
        if let Some(engine) = self.get_active_engine() {
            engine.compute_routes(dest_eid, contacts)
        } else {
            Vec::new()
        }
    }

    pub fn should_forward(&self, bundle: &Bundle, contact: &Contact) -> bool {
        if let Some(engine) = self.get_active_engine() {
            engine.should_forward(bundle, contact)
        } else {
            true
        }
    }

    pub fn update_contact(&self, contact: Contact) {
        if let Some(engine) = self.get_active_engine() {
            engine.update_contact(contact);
        }
    }

    pub fn list_engines(&self) -> Vec<String> {
        self.engines.read().keys().cloned().collect()
    }
}

impl Default for RoutingManager {
    fn default() -> Self {
        Self::new()
    }
} 