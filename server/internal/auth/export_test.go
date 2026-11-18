package auth

// ResetLimits forgets every rate limiter's state, so a test can make more
// attempts than a person would in a few seconds.
func (s *Service) ResetLimits() {
	s.ipLimit = NewKeyedLimiter(6e9, 10, 100_000)
	s.mfaLimit = NewKeyedLimiter(6e9, 10, 100_000)
	s.resetLimit = NewKeyedLimiter(20*60e9, 3, 100_000)
}
