# Expected Outputs of Unit Test

1\. Unit test output
```
$ ./unit 1

start: 1702969625851739048
end: 1702969625851811461
```

2\. NullFS output 
```
$ ./run.sh

...

rfuse experiment opcode: CREATE (35)
rfuse experiment [2]: 1702969625851797014 nsec
rfuse experiment [3]: 1702969625851797059 nsec
rfuse experiment [4]: 1702969625851797330 nsec
rfuse experiment [5]: 1702969625851797403 nsec
```

3\. kernel driver output
```
$ dmesg 

...

[ 1915.892150] rfuse experiment opcode: 35
[ 1915.892151] rfuse experiment [1]: 1702969625851791782 nsec
[ 1915.892152] rfuse experiment [6]: 1702969625851805610 nsec
[ 1915.892153] rfuse experiment [7]: 1702969625851805655 nsec
```

