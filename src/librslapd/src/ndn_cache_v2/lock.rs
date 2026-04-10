use std::ops::{Deref, DerefMut};

pub trait CacheLock<T>: Send + Sync {
    type ReadGuard<'a>: Deref<Target = T>
    where
        Self: 'a;
    type WriteGuard<'a>: DerefMut<Target = T>
    where
        Self: 'a;
    fn new(inner: T) -> Self;
    fn read(&self) -> Self::ReadGuard<'_>;
    fn write(&self) -> Self::WriteGuard<'_>;
}

impl<T: Send + Sync> CacheLock<T> for parking_lot::RwLock<T> {
    type ReadGuard<'a>
        = parking_lot::RwLockReadGuard<'a, T>
    where
        T: 'a;
    type WriteGuard<'a>
        = parking_lot::RwLockWriteGuard<'a, T>
    where
        T: 'a;
    fn new(inner: T) -> Self {
        parking_lot::RwLock::new(inner)
    }
    fn read(&self) -> Self::ReadGuard<'_> {
        self.read()
    }
    fn write(&self) -> Self::WriteGuard<'_> {
        self.write()
    }
}
