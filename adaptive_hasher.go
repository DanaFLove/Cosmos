adjuster := NewAdaptiveHasher(MinCost, MaxCost)
salt := []byte{ /* your salt */ }
password := []byte{ /* your password */ }

hash, err := adjuster.GenerateFromPassword(salt, password)
if err != nil {
    fmt.Println(err)
    return
}

fmt.Println(string(hash))
