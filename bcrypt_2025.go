package bcrypt

import (
    "crypto/subtle"
    "errors"
    "fmt"
    "strconv"
    "sync"

    "golang.org/x/crypto/blowfish"
)

const (
    MinCost     int = 4
    MaxCost     int = 31
    DefaultCost int = 10
)

// DynamicCostAdjuster adjusts the cost factor based on system load.
type DynamicCostAdjuster struct {
    minCost int
    maxCost int
    currentCost int
    mutex sync.Mutex
}

func (d *DynamicCostAdjuster) AdjustCost(load float64) {
    d.mutex.Lock()
    defer d.mutex.Unlock()
    
    // Example logic to adjust cost based on system load
    if load > 0.8 {
        d.currentCost = d.minCost
    } else if load < 0.2 {
        d.currentCost = d.maxCost
    } else {
        d.currentCost = (d.minCost + d.maxCost) / 2
    }
}

func (d *DynamicCostAdjuster) GetCost() int {
    d.mutex.Lock()
    defer d.mutex.Unlock()
    return d.currentCost
}

// AdaptiveHasher combines adaptive hashing with dynamic cost adjustment.
type AdaptiveHasher struct {
    adjuster *DynamicCostAdjuster
}

func NewAdaptiveHasher(minCost, maxCost int) *AdaptiveHasher {
    return &AdaptiveHasher{
        adjuster: &DynamicCostAdjuster{minCost: minCost, maxCost: maxCost},
    }
}

// GenerateFromPassword returns the bcrypt hash of the password at the given cost.
func (a *AdaptiveHasher) GenerateFromPassword(salt []byte, password []byte) ([]byte, error) {
    cost := a.adjuster.GetCost()
    return bcrypt(password, cost, salt)
}

// CompareHashAndPassword compares a bcrypt hashed password with its possible plaintext equivalent.
func (a *AdaptiveHasher) CompareHashAndPassword(hashedPassword, password []byte) error {
    return CompareHashAndPassword(hashedPassword, password)
}

// ParallelGenerateFromPassword uses parallel processing to speed up hashing.
func (a *AdaptiveHasher) ParallelGenerateFromPassword(salts [][]byte, passwords [][]byte) ([][]byte, error) {
    var wg sync.WaitGroup
    var mu sync.Mutex
    var results [][]byte

    for i := range passwords {
        wg.Add(1)
        go func(index int) {
            defer wg.Done()
            hash, err := a.GenerateFromPassword(salts[index], passwords[index])
            if err != nil {
                // Handle error
                return
            }
            mu.Lock()
            results = append(results, hash)
            mu.Unlock()
        }(i)
    }

    wg.Wait()
    return results, nil
}

// bcrypt generates the bcrypt hash of a password.
func bcrypt(password []byte, cost int, salt []byte) ([]byte, error) {
    if len(salt) != 16 {
        return nil, fmt.Errorf("salt len must be 16")
    }
    
    // Check cost validity
    if cost < MinCost || cost > MaxCost {
        return nil, InvalidCostError(cost)
    }

    cipherData := make([]byte, len(magicCipherData))
    copy(cipherData, magicCipherData)

    c, err := expensiveBlowfishSetup(password, uint32(cost), salt)
    if err != nil {
        return nil, err
    }

    for i := 0; i < 24; i += 8 {
        for j := 0; j < 64; j++ {
            c.Encrypt(cipherData[i:i+8], cipherData[i:i+8])
        }
    }

    hsh := base64Encode(cipherData[:23])
    return hsh, nil
}

// expensiveBlowfishSetup sets up the Blowfish cipher for bcrypt.
func expensiveBlowfishSetup(key []byte, cost uint32, salt []byte) (*blowfish.Cipher, error) {
    csalt, err := base64Decode(salt)
    if err != nil {
        return nil, err
    }

    ckey := append(key[:len(key):len(key)], 0)

    c, err := blowfish.NewSaltedCipher(ckey, csalt)
    if err != nil {
        return nil, err
    }

    var i, rounds uint64
    rounds = 1 << cost
    for i = 0; i < rounds; i++ {
        blowfish.ExpandKey(ckey, c)
        blowfish.ExpandKey(csalt, c)
    }

    return c, nil
}

// CompareHashAndPassword compares a bcrypt hashed password with its possible plaintext equivalent.
func CompareHashAndPassword(hashedPassword, password []byte) error {
    p, err := newFromHash(hashedPassword)
    if err != nil {
        return err
    }

    otherHash, err := bcrypt(password, p.cost, p.salt)
    if err != nil {
        return err
    }

    otherP := &hashed{otherHash, p.salt, p.cost, p.major, p.minor}
    if subtle.ConstantTimeCompare(p.Hash(), otherP.Hash()) == 1 {
        return nil
    }

    return ErrMismatchedHashAndPassword
}

// newFromHash reconstructs a hashed object from a bcrypt hash.
func newFromHash(hashedSecret []byte) (*hashed, error) {
    if len(hashedSecret) < 59 {
        return nil, ErrHashTooShort
    }
    p := new(hashed)
    n, err := p.decodeVersion(hashedSecret)
    if err != nil {
        return nil, err
    }
    hashedSecret = hashedSecret[n:]
    n, err = p.decodeCost(hashedSecret)
    if err != nil {
        return nil, err
    }
    hashedSecret = hashedSecret[n:]

    p.salt = make([]byte, 22)
    copy(p.salt, hashedSecret[:22])

    hashedSecret = hashedSecret[22:]
    p.hash = make([]byte, len(hashedSecret))
    copy(p.hash, hashedSecret)

    return p, nil
}

// hashed represents a bcrypt hashed password.
type hashed struct {
    hash  []byte
    salt  []byte
    cost  int
    major byte
    minor byte
}

func (p *hashed) Hash() []byte {
    arr := make([]byte, 60)
    arr[0] = '$'
    arr[1] = p.major
    n := 2
    if p.minor != 0 {
        arr[2] = p.minor
        n = 3
    }
    arr[n] = '$'
    n++
    copy(arr[n:], []byte(fmt.Sprintf("%02d", p.cost)))
    n += 2
    arr[n] = '$'
    n++
    copy(arr[n:], p.salt)
    n += 22
    copy(arr[n:], p.hash)
    n += len(p.hash)
    return arr[:n]
}

func (p *hashed) decodeVersion(sbytes []byte) (int, error) {
    if sbytes[0] != '$' {
        return -1, InvalidHashPrefixError(sbytes[0])
    }
    if sbytes[1] > majorVersion {
        return -1, HashVersionTooNewError(sbytes[1])
    }
    p.major = sbytes[1]
    n := 3
    if sbytes[2] != '$' {
        p.minor = sbytes[2]
        n++
    }
    return n, nil
}

func (p *hashed) decodeCost(sbytes []byte) (int, error) {
    cost, err := strconv.Atoi(string(sbytes[0:2]))
    if err != nil {
        return -1, err
    }
    err = checkCost(cost)
    if err != nil {
        return -1, err
    }
    p.cost = cost
    return 3, nil
}

// magicCipherData is an IV for the 64 Blowfish encryption calls in bcrypt().
var magicCipherData = []byte{
    0x4f, 0x72, 0x70, 0x68,
    0x65, 0x61, 0x6e, 0x42,
    0x65, 0x68, 0x6f, 0x6c,
    0x64, 0x65, 0x72, 0x53,
    0x63, 0x72, 0x79, 0x44,
    0x6f, 0x75, 0x62, 0x74,
}

const majorVersion = '2'
const minorVersion = 'a'

// InvalidCostError is returned when the cost is outside the allowed range.
type InvalidCostError int

func (ic InvalidCostError) Error() string {
    return fmt.Sprintf("crypto/bcrypt: cost %d is outside allowed range (%d,%d)", int(ic), int(MinCost), int(MaxCost))
}

// InvalidHashPrefixError is returned when a hash does not start with '$'.
type InvalidHashPrefixError byte

func (ih InvalidHashPrefixError) Error() string {
    return fmt.Sprintf("crypto/bcrypt: bcrypt hashes must start with '$', but hashedSecret started with '%c'", byte(ih))
}

// HashVersionTooNewError is returned when a hash uses a newer bcrypt version.
type HashVersionTooNewError byte

func (hv HashVersionTooNewError) Error() string {
    return fmt.Sprintf("crypto/bcrypt: bcrypt algorithm version '%c' requested is newer than current version '%c'", byte(hv), majorVersion)
}

// ErrMismatchedHashAndPassword is returned when a password and hash do not match.
var ErrMismatchedHashAndPassword = errors.New("crypto/bcrypt: hashedPassword is not the hash of the given password")

// ErrHashTooShort is returned when a hash is too short to be a bcrypt hash.
var ErrHashTooShort = errors.New("crypto/bcrypt: hashedSecret too short to be a bcrypted password")

func checkCost(cost int) error {
    if cost < MinCost || cost > MaxCost {
        return InvalidCostError(cost)
    }
    return nil
}

func main() {
    adjuster := NewAdaptiveHasher(MinCost, MaxCost)
    salt := []byte{ /* your salt */ }
    password := []byte{ /* your password */ }
    
    // Example usage
    hash, err := adjuster.GenerateFromPassword(salt, password)
    if err != nil {
        fmt.Println(err)
        return
    }
    
    fmt.Println(string(hash))
}
