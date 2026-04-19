#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp {
    Equal { old_idx: usize, new_idx: usize },
    Insert { new_idx: usize },
    Delete { old_idx: usize },
}

pub fn diff_lines(old: &[&str], new: &[&str]) -> Vec<DiffOp> {
    let n = old.len();
    let m = new.len();
    let max = n + m;
    let mut trace: Vec<Vec<i64>> = Vec::new();
    let mut v = vec![0i64; 2 * max + 1];
    let offset = max as i64;

    let mut reached = None;
    'outer: for d in 0..=max {
        let d_i = d as i64;
        let mut x;
        let mut y;
        let k_range: Vec<i64> = (-(d_i)..=d_i).step_by(2).collect();
        let saved = v.clone();
        for &k in &k_range {
            let idx = (k + offset) as usize;
            if k == -d_i
                || (k != d_i && v[(k - 1 + offset) as usize] < v[(k + 1 + offset) as usize])
            {
                x = v[(k + 1 + offset) as usize];
            } else {
                x = v[(k - 1 + offset) as usize] + 1;
            }
            y = x - k;
            while x < n as i64 && y < m as i64 && old[x as usize] == new[y as usize] {
                x += 1;
                y += 1;
            }
            v[idx] = x;
            if x >= n as i64 && y >= m as i64 {
                trace.push(saved);
                reached = Some(d);
                break 'outer;
            }
        }
        trace.push(saved);
    }

    let d_final = reached.unwrap_or(0);

    let mut ops: Vec<DiffOp> = Vec::new();
    let mut x = n as i64;
    let mut y = m as i64;
    for d in (0..=d_final).rev() {
        let vprev = &trace[d];
        let k = x - y;
        let prev_k = if k == -(d as i64)
            || (k != d as i64
                && vprev[(k - 1 + offset) as usize] < vprev[(k + 1 + offset) as usize])
        {
            k + 1
        } else {
            k - 1
        };
        let prev_x = vprev[(prev_k + offset) as usize];
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            ops.push(DiffOp::Equal {
                old_idx: (x - 1) as usize,
                new_idx: (y - 1) as usize,
            });
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            if x == prev_x {
                ops.push(DiffOp::Insert {
                    new_idx: (y - 1) as usize,
                });
            } else {
                ops.push(DiffOp::Delete {
                    old_idx: (x - 1) as usize,
                });
            }
            x = prev_x;
            y = prev_y;
        }
    }
    ops.reverse();
    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_is_all_equal() {
        let a = vec!["one", "two", "three"];
        let ops = diff_lines(&a, &a);
        assert_eq!(ops.len(), 3);
        for op in &ops {
            assert!(matches!(op, DiffOp::Equal { .. }));
        }
    }

    #[test]
    fn all_inserted() {
        let a: Vec<&str> = vec![];
        let b = vec!["a", "b"];
        let ops = diff_lines(&a, &b);
        assert_eq!(ops.len(), 2);
        assert!(ops.iter().all(|o| matches!(o, DiffOp::Insert { .. })));
    }

    #[test]
    fn all_deleted() {
        let a = vec!["a", "b"];
        let b: Vec<&str> = vec![];
        let ops = diff_lines(&a, &b);
        assert_eq!(ops.len(), 2);
        assert!(ops.iter().all(|o| matches!(o, DiffOp::Delete { .. })));
    }

    #[test]
    fn middle_insertion() {
        let a = vec!["a", "c"];
        let b = vec!["a", "b", "c"];
        let ops = diff_lines(&a, &b);
        assert_eq!(ops.len(), 3);
        assert!(matches!(ops[0], DiffOp::Equal { .. }));
        assert!(matches!(ops[1], DiffOp::Insert { new_idx: 1 }));
        assert!(matches!(ops[2], DiffOp::Equal { .. }));
    }

    #[test]
    fn single_change() {
        let a = vec!["a", "b", "c"];
        let b = vec!["a", "x", "c"];
        let ops = diff_lines(&a, &b);
        let inserts = ops
            .iter()
            .filter(|o| matches!(o, DiffOp::Insert { .. }))
            .count();
        let deletes = ops
            .iter()
            .filter(|o| matches!(o, DiffOp::Delete { .. }))
            .count();
        assert_eq!(inserts, 1);
        assert_eq!(deletes, 1);
    }
}
