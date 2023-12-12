## R1CS customized lazy inputs usage

### 1. identify the duplicated structure

* e.g. in Poseidon we perform the permutation many times.
* e.g. in MiMC we perform the permutation many times.

### 2. create lazy definition(indexed by “key”) in constraint/lazy package, and register as below
```go=
    constraint.Register(key, createGeneralLazyInputsFunc(key))
```

### 3.record constraint for lazy, remember to match the key defined above
```go=
    api.StartRecordConstraintsForLazy(cs.GetLazyPoseidonKey(len(state)), state...)
    // the code that generates repeated constraints
    api.EndRecordConstraintsForLazy(cs.GetLazyPoseidonKey(len(state)), state...)
```

### 4.call lazify of the constraint system, to compress repeated constraints