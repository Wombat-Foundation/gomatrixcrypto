package reconcile

type polynomial []uint64

const (
	fieldBits           = 64
	mixedFactorTrials   = 8
	factorTrials        = mixedFactorTrials + fieldBits
	factorParameterSeed = 0x9e37_79b9_7f4a_7c15
	traceSquares        = 63
	maxFactorWork       = 8_000_000
)

func decodePinSketch(oddSyndromes []uint64, maxElements int) ([]uint64, error) {
	all := reconstructSyndromes(oddSyndromes)
	locator, ok := berlekampMassey(all, maxElements)
	if !ok {
		return nil, ErrDecodeFailure
	}
	if len(locator) == 1 {
		return []uint64{}, nil
	}
	reverseUint64s(locator)
	expected := len(locator) - 1
	roots := make([]uint64, 0, expected)
	if err := findRoots(locator, &roots); err != nil {
		return nil, err
	}
	if len(roots) != expected || containsZero(roots) {
		return nil, ErrDecodeFailure
	}
	sortUint64s(roots)
	return roots, nil
}

func reconstructSyndromes(odd []uint64) []uint64 {
	all := make([]uint64, len(odd)*2)
	for index, value := range odd {
		all[index*2] = value
		all[index*2+1] = Mul(all[index], all[index])
	}
	return all
}

func berlekampMassey(syndromes []uint64, maxDegree int) (polynomial, bool) {
	current := polynomial{1}
	previous := polynomial{1}
	previousDiscrepancy := uint64(1)

	for n, syndrome := range syndromes {
		discrepancy := syndrome
		for i, coefficient := range current {
			if i == 0 || n < i {
				continue
			}
			syndromeIndex := n - i
			discrepancy ^= Mul(syndromes[syndromeIndex], coefficient)
		}
		if discrepancy == 0 {
			continue
		}

		currentDegree := len(current) - 1
		previousDegree := len(previous) - 1
		shift := n + 1 - currentDegree - previousDegree
		swap := currentDegree*2 <= n
		oldCurrent := append(polynomial(nil), current...)
		if swap {
			newLen := len(previous) + shift
			if newLen-1 > maxDegree {
				return nil, false
			}
			if newLen > len(current) {
				current = append(current, make([]uint64, newLen-len(current))...)
			}
		}
		inv, ok := gf64Inv(previousDiscrepancy)
		if !ok {
			return nil, false
		}
		scale := Mul(discrepancy, inv)
		for i, coefficient := range previous {
			target := i + shift
			current[target] ^= Mul(scale, coefficient)
		}
		if swap {
			previous = oldCurrent
			previousDiscrepancy = discrepancy
		}
	}
	if len(current) == 0 || current[len(current)-1] == 0 {
		return nil, false
	}
	return current, true
}

func gf64Inv(value uint64) (uint64, bool) {
	if value == 0 {
		return 0, false
	}
	var result uint64 = 1
	exponent := ^uint64(0) - 1
	for bit := 63; bit >= 0; bit-- {
		result = Mul(result, result)
		if exponent&(1<<uint(bit)) != 0 {
			result = Mul(result, value)
		}
		if bit == 0 {
			break
		}
	}
	return result, true
}

func trim(poly *polynomial) {
	for len(*poly) > 0 && (*poly)[len(*poly)-1] == 0 {
		*poly = (*poly)[:len(*poly)-1]
	}
}

func makeMonic(poly *polynomial) bool {
	if len(*poly) == 0 {
		return false
	}
	leading := (*poly)[len(*poly)-1]
	if leading == 1 {
		return true
	}
	inverse, ok := gf64Inv(leading)
	if !ok {
		return false
	}
	for i := range *poly {
		(*poly)[i] = Mul((*poly)[i], inverse)
	}
	return true
}

func polyMod(modulus []uint64, value *polynomial) bool {
	modulusDegree := len(modulus) - 1
	if len(modulus) == 0 || modulus[len(modulus)-1] != 1 {
		return false
	}
	for len(*value) >= len(modulus) {
		term := (*value)[len(*value)-1]
		*value = (*value)[:len(*value)-1]
		if term != 0 {
			offset := len(*value) - modulusDegree
			if offset < 0 {
				return false
			}
			for index, coefficient := range modulus[:modulusDegree] {
				(*value)[offset+index] ^= Mul(term, coefficient)
			}
		}
	}
	trim(value)
	return true
}

func polyDiv(dividend polynomial, divisor []uint64) (polynomial, bool) {
	if len(divisor) == 0 || divisor[len(divisor)-1] != 1 || len(dividend) < len(divisor) {
		return nil, false
	}
	quotient := make(polynomial, len(dividend)-len(divisor)+1)
	divisorDegree := len(divisor) - 1
	for len(dividend) >= len(divisor) {
		term := dividend[len(dividend)-1]
		dividend = dividend[:len(dividend)-1]
		position := len(dividend) - divisorDegree
		if position < 0 {
			return nil, false
		}
		quotient[position] = term
		if term != 0 {
			for index, coefficient := range divisor[:divisorDegree] {
				dividend[position+index] ^= Mul(term, coefficient)
			}
		}
	}
	trim(&quotient)
	return quotient, true
}

func polyGCD(left, right polynomial) (polynomial, bool) {
	if len(left) < len(right) {
		left, right = right, left
	}
	for len(right) != 0 {
		if !makeMonic(&right) {
			return nil, false
		}
		if !polyMod(right, &left) {
			return nil, false
		}
		left, right = right, left
	}
	if !makeMonic(&left) {
		return nil, false
	}
	return left, true
}

func polySquare(poly *polynomial) bool {
	if len(*poly) == 0 {
		return true
	}
	newLen := len(*poly)*2 - 1
	old := append(polynomial(nil), *poly...)
	*poly = make(polynomial, newLen)
	for i, coefficient := range old {
		(*poly)[i*2] = Mul(coefficient, coefficient)
	}
	return true
}

func traceMod(modulus []uint64, parameter uint64) (polynomial, bool) {
	trace := polynomial{0, parameter}
	for i := 0; i < traceSquares; i++ {
		if !polySquare(&trace) {
			return nil, false
		}
		if len(trace) < 2 {
			trace = append(trace, make([]uint64, 2-len(trace))...)
		}
		trace[1] = parameter
		if !polyMod(modulus, &trace) {
			return nil, false
		}
	}
	return trace, true
}

func nextFactorParameter(state uint64) uint64 {
	state ^= state << 13
	state ^= state >> 7
	return state ^ (state << 17)
}

func solveQuadraticForm(target uint64) (uint64, bool) {
	type row struct {
		coefficients uint64
		rhs          bool
	}

	rows := make([]row, 64)
	for column := 0; column < 64; column++ {
		basis := uint64(1) << uint(column)
		image := Mul(basis, basis) ^ basis
		for r := 0; r < 64; r++ {
			if image&(uint64(1)<<uint(r)) != 0 {
				rows[r].coefficients |= uint64(1) << uint(column)
			}
		}
	}
	for r := 0; r < 64; r++ {
		if target&(uint64(1)<<uint(r)) != 0 {
			rows[r].rhs = true
		}
	}

	rank := 0
	for column := 0; column < 64; column++ {
		pivot := -1
		for row := rank; row < 64; row++ {
			if rows[row].coefficients&(uint64(1)<<uint(column)) != 0 {
				pivot = row
				break
			}
		}
		if pivot < 0 {
			continue
		}
		rows[rank], rows[pivot] = rows[pivot], rows[rank]
		pivotRow := rows[rank]
		for row := 0; row < 64; row++ {
			if row != rank && rows[row].coefficients&(uint64(1)<<uint(column)) != 0 {
				rows[row].coefficients ^= pivotRow.coefficients
				rows[row].rhs = rows[row].rhs != pivotRow.rhs
			}
		}
		rank++
	}
	for _, row := range rows {
		if row.coefficients == 0 && row.rhs {
			return 0, false
		}
	}
	var solution uint64
	for _, row := range rows[:rank] {
		if row.coefficients == 0 {
			return 0, false
		}
		pivot := trailingZeros64(row.coefficients)
		if row.rhs {
			solution |= uint64(1) << uint(pivot)
		}
	}
	if Mul(solution, solution)^solution != target {
		return 0, false
	}
	return solution, true
}

func findRoots(poly polynomial, roots *[]uint64) error {
	work := maxFactorWork
	return findRootsWithBudget(poly, roots, &work)
}

func factorTrialCost(degree int) (int, bool) {
	if degree < 0 {
		return 0, false
	}
	if degree == 0 {
		return 0, true
	}
	if degree > maxInt/degree {
		return 0, false
	}
	value := degree * degree
	if value > maxInt/traceSquares {
		return 0, false
	}
	return value * traceSquares, true
}

func findRootsWithBudget(poly polynomial, roots *[]uint64, work *int) error {
	pending := []polynomial{poly}
	for len(pending) > 0 {
		poly := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		degree := len(poly) - 1
		if degree < 0 {
			return ErrDecodeFailure
		}
		switch degree {
		case 0:
			continue
		case 1:
			*roots = append(*roots, poly[0])
			continue
		case 2:
			linear := poly[1]
			if linear == 0 {
				return ErrDecodeFailure
			}
			inverse, ok := gf64Inv(linear)
			if !ok {
				return ErrDecodeFailure
			}
			normalized := Mul(poly[0], Mul(inverse, inverse))
			quadratic, ok := solveQuadraticForm(normalized)
			if !ok {
				return ErrDecodeFailure
			}
			root := Mul(quadratic, linear)
			*roots = append(*roots, root, root^linear)
			continue
		}

		var split bool
		parameter := uint64(factorParameterSeed)
		for trial := 0; trial < factorTrials; trial++ {
			if trial >= mixedFactorTrials {
				basisBit := trial - mixedFactorTrials
				if basisBit < 0 || basisBit >= 64 {
					return ErrDecodeFailure
				}
				parameter = uint64(1) << uint(basisBit)
			}
			cost, ok := factorTrialCost(degree)
			if !ok {
				return ErrDecodeFailure
			}
			*work -= cost
			if *work < 0 {
				return ErrBudgetExhausted
			}
			trace, ok := traceMod(poly, parameter)
			if !ok {
				return ErrDecodeFailure
			}
			factor, ok := polyGCD(append(polynomial(nil), poly...), trace)
			if !ok {
				return ErrDecodeFailure
			}
			if len(factor) > 1 && len(factor) < len(poly) {
				quotient, ok := polyDiv(poly, factor)
				if !ok {
					return ErrDecodeFailure
				}
				pending = append(pending, quotient, factor)
				split = true
				break
			}
			if trial < mixedFactorTrials {
				parameter = nextFactorParameter(parameter)
			}
		}
		if !split {
			return ErrDecodeFailure
		}
	}
	return nil
}

func reverseUint64s(values []uint64) {
	for i, j := 0, len(values)-1; i < j; i, j = i+1, j-1 {
		values[i], values[j] = values[j], values[i]
	}
}

func sortUint64s(values []uint64) {
	if len(values) < 2 {
		return
	}
	for i := 1; i < len(values); i++ {
		v := values[i]
		j := i - 1
		for j >= 0 && values[j] > v {
			values[j+1] = values[j]
			j--
		}
		values[j+1] = v
	}
}

func trailingZeros64(v uint64) int {
	if v == 0 {
		return 64
	}
	n := 0
	for (v & 1) == 0 {
		n++
		v >>= 1
	}
	return n
}
