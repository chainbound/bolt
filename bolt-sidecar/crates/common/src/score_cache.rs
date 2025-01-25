use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt::Debug,
    hash::{BuildHasher, Hash, RandomState},
    ops::{Deref, DerefMut},
};

/// [ScoreCache] provides a hash map-like data structure with an additional scoring mechanism. Each
/// entry in the cache is assigned a score, which is modified based on specific operations (GET,
/// INSERT, UPDATE).
/// The cache has a maximum length (max_len), and when this length is exceeded,
/// stale elements (entries with the lowest scores) are removed to make space for new entries.
///
/// The module is particularly useful for scenarios where a priority-based
/// eviction policy is required.
pub struct ScoreCache<
    const GET_SCORE: isize,
    const INSERT_SCORE: isize,
    const UPDATE_SCORE: isize,
    K,
    V,
    S = RandomState,
> {
    map: HashMap<K, (V, isize), S>,
    max_len: usize,
}

// -------- TRAITS --------

impl<const GET_SCORE: isize, const INSERT_SCORE: isize, const UPDATE_SCORE: isize, K, V> Default
    for ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, K, V, RandomState>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const GET_SCORE: isize, const INSERT_SCORE: isize, const UPDATE_SCORE: isize, K, V, S> Deref
    for ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, K, V, S>
{
    type Target = HashMap<K, (V, isize), S>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<const GET_SCORE: isize, const INSERT_SCORE: isize, const UPDATE_SCORE: isize, K, V, S> DerefMut
    for ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, K, V, S>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

impl<
        const GET_SCORE: isize,
        const INSERT_SCORE: isize,
        const UPDATE_SCORE: isize,
        K: Debug,
        V: Debug,
        S,
    > Debug for ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, K, V, S>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScoreCache")
            .field("map", &self.map)
            .field("max_len", &self.max_len)
            .finish()
    }
}

// -------- INIT IMPLEMENTATIONS --------

impl<const GET_SCORE: isize, const INSERT_SCORE: isize, const UPDATE_SCORE: isize, K, V>
    ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, K, V, RandomState>
{
    /// Creates an empty `ScoreMap` without maximum length.
    ///
    /// See also [std::collections::HashMap::new].
    #[inline]
    pub fn new() -> Self {
        Self { map: HashMap::<K, (V, isize)>::new(), max_len: usize::MAX }
    }

    /// Creates an empty `ScoreMap` with maximum length.
    ///
    /// See also [std::collections::HashMap::new].
    #[inline]
    pub fn with_max_len(max_len: usize) -> Self {
        Self { map: HashMap::<K, (V, isize)>::new(), max_len }
    }

    /// Creates an empty `HashMap` with at least the specified capacity.
    ///
    /// See also [std::collections::HashMap::with_capacity].
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self { map: HashMap::<K, (V, isize)>::with_capacity(capacity), max_len: usize::MAX }
    }

    /// Creates an empty `HashMap` with at least the specified capacity and maximum length.
    #[inline]
    pub fn with_capacity_and_len(capacity: usize, max_len: usize) -> Self {
        Self { map: HashMap::<K, (V, isize)>::with_capacity(capacity), max_len }
    }
}

impl<const GET_SCORE: isize, const INSERT_SCORE: isize, const UPDATE_SCORE: isize, K, V, S>
    ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, K, V, S>
{
    /// See [std::collections::HashMap::with_hasher].
    #[inline]
    pub fn with_hasher(hash_builder: S) -> Self {
        Self { map: HashMap::with_hasher(hash_builder), max_len: usize::MAX }
    }

    /// See [std::collections::HashMap::with_capacity_and_hasher].
    #[inline]
    pub fn with_capacity_and_hasher(capacity: usize, hasher: S) -> Self {
        Self { map: HashMap::with_capacity_and_hasher(capacity, hasher), max_len: usize::MAX }
    }

    /// Creates a score map with the specified capacity, hasher, and length.
    ///
    /// See [std::collections::HashMap::with_capacity_and_hasher].
    #[inline]
    pub fn with_capacity_and_hasher_and_max_len(
        capacity: usize,
        hasher: S,
        max_len: usize,
    ) -> Self {
        Self { map: HashMap::with_capacity_and_hasher(capacity, hasher), max_len }
    }
}

// -------- METHODS --------

impl<const GET_SCORE: isize, const INSERT_SCORE: isize, const UPDATE_SCORE: isize, K, V, S>
    ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, K, V, S>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    /// A wrapper over [std::collections::HashMap::get_mut] that bumps the score of the key.
    ///
    /// Requires mutable access to the cache to update the score.
    #[inline]
    pub fn get<Q>(&mut self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get_mut(k).map(|(v, score)| {
            *score = score.saturating_add(GET_SCORE);
            &*v
        })
    }

    /// A wrapper over [std::collections::HashMap::get_mut] that bumps the score of the key.
    ///
    /// Requires mutable access to the cache to update the score.
    #[inline]
    pub fn get_mut<Q>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get_mut(k).map(|(v, score)| {
            *score = score.saturating_add(UPDATE_SCORE);
            v
        })
    }

    /// A wrapper over [std::collections::HashMap::insert] that bumps the score of the key.
    ///
    /// Adds a new key-value pair to the cache with the provided `INSERT_SCORE`, by first trying to
    /// clear any stale element from the cache if necessary.
    #[inline]
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.clear_stales();
        self.map.insert(k, (v, INSERT_SCORE)).map(|(v, _)| v)
    }
}

impl<const GET_SCORE: isize, const INSERT_SCORE: isize, const UPDATE_SCORE: isize, K, V, S>
    ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, K, V, S>
{
    // Clear the stale values from the cache if there is any.
    #[inline]
    fn clear_stales(&mut self) {
        let mut i = 0;
        while self.len() >= self.max_len {
            self.map.retain(|_, (_, score)| *score > i);
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GET_SCORE: isize = 4;
    const INSERT_SCORE: isize = 4;
    const UPDATE_SCORE: isize = -1;

    fn default_score_cache() -> ScoreCache<GET_SCORE, INSERT_SCORE, UPDATE_SCORE, usize, String> {
        ScoreCache::with_max_len(2)
    }

    #[test]
    fn test_score_logic_2() {
        let mut cache = default_score_cache();

        cache.insert(1, "one".to_string());
        assert_eq!(cache.map.get(&1), Some(&("one".to_string(), GET_SCORE)));

        assert_eq!(cache.get(&1), Some(&"one".to_string()));
        assert_eq!(cache.map.get(&1), Some(&("one".to_string(), GET_SCORE * 2)));

        let v = cache.get_mut(&1).unwrap();
        *v = "one".to_string();
        assert_eq!(cache.map.get(&1), Some(&("one".to_string(), GET_SCORE * 2 + UPDATE_SCORE)));

        // Insert a new value and update it to set its score to zero.
        cache.insert(2, "two".to_string());
        for _ in 0..GET_SCORE {
            let v = cache.get_mut(&2).unwrap();
            *v = "two".to_string();
        }
        assert_eq!(cache.map.get(&2), Some(&("two".to_string(), 0)));

        // Insert a new value: "2" should be dropped.
        cache.insert(3, "three".to_string());
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.map.get(&2), None);
    }
}
