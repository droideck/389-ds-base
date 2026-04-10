const OU_NAMES: &[&str] = &[
    "Technology",
    "Engineering",
    "Sales",
    "Marketing",
    "Human Resources",
    "Quality Assurance",
    "Operations",
    "Legal",
    "Customer Service",
    "General Management",
    "Information Technology",
    "Creative Services",
    "Business Development",
    "Product Management",
    "Asset Management",
    "Board of Directors",
];

const DC_SUFFIX: &str = "dc=example,dc=com";

pub fn generate_corpus(n: usize, seed: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rng = SimpleRng::new(seed);
    let mut corpus = Vec::with_capacity(n);

    for i in 0..n {
        let depth = 3 + (rng.next_u32() % 4) as usize;
        let ou_idx = (rng.next_u32() as usize) % OU_NAMES.len();
        let ou = OU_NAMES[ou_idx];

        let raw = match depth {
            3 => format!("uid=user{:06},ou={},{}", i, ou, DC_SUFFIX),
            4 => {
                let sub_ou_idx = (rng.next_u32() as usize) % OU_NAMES.len();
                format!(
                    "uid=user{:06},ou=Team{},ou={},{}",
                    i,
                    sub_ou_idx % 20,
                    ou,
                    DC_SUFFIX
                )
            }
            5 => {
                let sub_ou_idx = (rng.next_u32() as usize) % OU_NAMES.len();
                let sub2 = (rng.next_u32() % 10) as usize;
                format!(
                    "uid=user{:06},ou=Division{},ou=Team{},ou={},{}",
                    i,
                    sub2,
                    sub_ou_idx % 20,
                    ou,
                    DC_SUFFIX
                )
            }
            _ => {
                let sub_ou_idx = (rng.next_u32() as usize) % OU_NAMES.len();
                let sub2 = (rng.next_u32() % 10) as usize;
                let sub3 = (rng.next_u32() % 5) as usize;
                format!(
                    "cn=Resource{},ou=Division{},ou=Team{},ou={},{}",
                    sub3,
                    sub2,
                    sub_ou_idx % 20,
                    ou,
                    DC_SUFFIX
                )
            }
        };

        let normalized = raw.to_lowercase();
        corpus.push((raw.into_bytes(), normalized.into_bytes()));
    }

    corpus
}

struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_generates_correct_count() {
        let corpus = generate_corpus(1000, 42);
        assert_eq!(corpus.len(), 1000);
    }

    #[test]
    fn corpus_has_varied_depths() {
        let corpus = generate_corpus(1000, 42);
        let depths: Vec<usize> = corpus
            .iter()
            .map(|(raw, _)| raw.split(|&b| b == b',').count())
            .collect();
        let min_depth = *depths.iter().min().unwrap();
        let max_depth = *depths.iter().max().unwrap();
        assert!(
            min_depth >= 3,
            "min depth should be >= 3, got {}",
            min_depth
        );
        assert!(
            max_depth >= 5,
            "max depth should be >= 5, got {}",
            max_depth
        );
    }

    #[test]
    fn normalized_is_lowercase() {
        let corpus = generate_corpus(100, 42);
        for (_, norm) in &corpus {
            let s = std::str::from_utf8(norm).unwrap();
            assert_eq!(s, s.to_lowercase());
        }
    }

    #[test]
    fn deterministic_output() {
        let c1 = generate_corpus(100, 42);
        let c2 = generate_corpus(100, 42);
        assert_eq!(c1, c2);
    }
}
