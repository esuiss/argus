use crate::pkce::Sha256;

// RFC 6962'nin alan ayrımı. Bu önekler olmadan, baytları iki birleştirilmiş
// hash'e benzeyen bir yaprak bir iç düğümün yerine geçebilir ve n yapraklı
// ağacın ikinci ön-görüntüsü olur.
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

#[must_use]
// §9.3: ağaç bir performans tercihi değil, kanıt uç noktasını bir ürün
// yeteneği hâline getiren şeydir. Hash zinciri bunu hiç veremez.
pub fn leaf_hash<H: Sha256>(hasher: &H, data: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(data.len() + 1);
    input.push(LEAF_PREFIX);
    input.extend_from_slice(data);
    hasher.sha256(&input)
}

#[must_use]
pub fn node_hash<H: Sha256>(hasher: &H, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0_u8; 65];
    if let Some(slot) = input.first_mut() {
        *slot = NODE_PREFIX;
    }
    if let Some(slot) = input.get_mut(1..33) {
        slot.copy_from_slice(left);
    }
    if let Some(slot) = input.get_mut(33..65) {
        slot.copy_from_slice(right);
    }
    hasher.sha256(&input)
}

// n'den kesin küçük en büyük ikinin kuvveti. RFC 6962 her alt ağacı burada
// böler ve kanıtların bütün şekli bundan çıkar.
const fn split(n: usize) -> usize {
    if n < 2 {
        return 0;
    }
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

#[must_use]
pub fn root<H: Sha256>(hasher: &H, leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves {
        [] => hasher.sha256(&[]),
        [only] => *only,
        many => {
            let k = split(many.len());
            let (left, right) = many.split_at(k);
            node_hash(hasher, &root(hasher, left), &root(hasher, right))
        }
    }
}

#[must_use]
// `index`'in iddia ettiği yaprak olduğunu kanıtlayan kardeş hash'ler. Tek
// yapraklı ağaçta boş, indeks ağaçta değilse None.
pub fn inclusion_proof<H: Sha256>(
    hasher: &H,
    leaves: &[[u8; 32]],
    index: usize,
) -> Option<Vec<[u8; 32]>> {
    if index >= leaves.len() {
        return None;
    }
    if leaves.len() == 1 {
        return Some(Vec::new());
    }

    let k = split(leaves.len());
    let (left, right) = leaves.split_at(k);

    let mut proof = if index < k {
        inclusion_proof(hasher, left, index)?
    } else {
        inclusion_proof(hasher, right, index - k)?
    };

    proof.push(if index < k {
        root(hasher, right)
    } else {
        root(hasher, left)
    });

    Some(proof)
}

#[must_use]
// RFC 6962 §2.1.1, adım adım. Kanıt en derin kardeşten dışarı doğru sıralıdır,
// dolayısıyla doğrulama iner değil TIRMANIR; bu yönü yanlış yapmak dengeli
// ağaçları yine de doğrular ve yalnızca tek sayılı boyutlarda düşer — bu hata
// tam olarak böyle yakalandı.
pub fn verify_inclusion<H: Sha256>(
    hasher: &H,
    leaf: &[u8; 32],
    index: usize,
    size: usize,
    proof: &[[u8; 32]],
    expected: &[u8; 32],
) -> bool {
    if index >= size || size == 0 {
        return false;
    }

    let mut fnode = index;
    let mut snode = size - 1;
    let mut r = *leaf;

    for p in proof {
        if snode == 0 {
            return false;
        }

        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(hasher, p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(hasher, &r, p);
        }

        fnode >>= 1;
        snode >>= 1;
    }

    snode == 0 && r == *expected
}

#[must_use]
// `old_size` yapraklı bir ağacın mevcut ağacın öneki olduğunu kanıtlar.
// §9.3'ün üçüncü kararı buna muhtaç: yayınlanmış bir checkpoint, operatör
// geçmişi yeniden yazıp taze bir kök yayınlayabiliyorsa hiçbir şey ifade
// etmez.
pub fn consistency_proof<H: Sha256>(
    hasher: &H,
    leaves: &[[u8; 32]],
    old_size: usize,
) -> Option<Vec<[u8; 32]>> {
    if old_size == 0 || old_size > leaves.len() {
        return None;
    }
    Some(subproof(hasher, old_size, leaves, true))
}

fn subproof<H: Sha256>(hasher: &H, m: usize, leaves: &[[u8; 32]], complete: bool) -> Vec<[u8; 32]> {
    // Eski ağaç tam olarak bu alt ağaçtır. Üstündeki düğümün tamamıysa
    // doğrulayıcı kökünü zaten elinde tutar ve hiçbir şeye ihtiyacı yoktur.
    if m == leaves.len() {
        return if complete {
            Vec::new()
        } else {
            vec![root(hasher, leaves)]
        };
    }

    let k = split(leaves.len());
    let (left, right) = leaves.split_at(k);

    if m <= k {
        let mut out = subproof(hasher, m, left, complete);
        out.push(root(hasher, right));
        out
    } else {
        let mut out = subproof(hasher, m - k, right, false);
        out.push(root(hasher, left));
        out
    }
}

#[must_use]
// RFC 6962 §2.1.2, adım adım.
pub fn verify_consistency<H: Sha256>(
    hasher: &H,
    old_size: usize,
    old_root: &[u8; 32],
    new_size: usize,
    new_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if old_size == 0 || old_size > new_size {
        return false;
    }

    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }

    // Bütün bir alt ağaç olan ilk ağaç kendi kökünü katkı verir, dolayısıyla
    // kanıtlayan onu hiç göndermez.
    let mut path: Vec<[u8; 32]> = Vec::with_capacity(proof.len() + 1);
    if old_size.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);

    let Some((first, rest)) = path.split_first() else {
        return false;
    };

    let mut fnode = old_size - 1;
    let mut snode = new_size - 1;

    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }

    let mut fr = *first;
    let mut sr = *first;

    for c in rest {
        if snode == 0 {
            return false;
        }

        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(hasher, c, &fr);
            sr = node_hash(hasher, c, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = node_hash(hasher, &sr, c);
        }

        fnode >>= 1;
        snode >>= 1;
    }

    snode == 0 && fr == *old_root && sr == *new_root
}
