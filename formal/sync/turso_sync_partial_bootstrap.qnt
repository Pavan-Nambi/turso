module turso_sync_partial_bootstrap {
  pure val PAGE_SIZE: int = 4
  pure val DB_PAGE_COUNT: int = 4
  pure val PAGES: Set[int] = 0.to(DB_PAGE_COUNT - 1)
  pure val LENGTHS: Set[int] = 0.to(12)
  pure val CHUNK_PAGES: Set[int] = 0.to(2)
  pure val NO_LENGTH: int = -1

  var prefixLength: int
  var chunkPages: int
  var firstSelector: Set[int]
  var rustFetched: Set[int]
  var expectedFetched: Set[int]
  var chunkRequestsPinned: bool
  var didBootstrap: bool

  // Pages intersecting the byte prefix [0, length). This is ceil(length /
  // PAGE_SIZE), bounded by the modeled remote DB size.
  def expectedPageCount(prefixBytes: int): int =
    if (prefixBytes == 0) {
      0
    } else if (prefixBytes <= 4) {
      1
    } else if (prefixBytes <= 8) {
      2
    } else if (prefixBytes <= 12) {
      3
    } else {
      4
    }

  // Current Rust implementation computes length / PAGE_SIZE with floor
  // division before constructing [0, prefix_bootstrap_last_page_id).
  def rustFloorPageCount(prefixBytes: int): int =
    if (prefixBytes < 4) {
      0
    } else if (prefixBytes < 8) {
      1
    } else if (prefixBytes < 12) {
      2
    } else {
      3
    }

  def pagePrefix(count: int): Set[int] =
    if (count <= 0) {
      Set()
    } else if (count == 1) {
      Set(0)
    } else if (count == 2) {
      Set(0, 1)
    } else if (count == 3) {
      Set(0, 1, 2)
    } else {
      PAGES
    }

  action init = all {
    prefixLength' = NO_LENGTH,
    chunkPages' = 0,
    firstSelector' = Set(),
    rustFetched' = Set(),
    expectedFetched' = Set(),
    chunkRequestsPinned' = true,
    didBootstrap' = false,
  }

  action bootstrapPrefix = {
    nondet prefixBytes = LENGTHS.oneOf()
    nondet chunk = CHUNK_PAGES.oneOf()
    bootstrapPrefixFor(prefixBytes, chunk)
  }

  action bootstrapPrefixFor(prefixBytes: int, chunk: int): bool = {
    val expectedCount = expectedPageCount(prefixBytes)
    val rustCount = rustFloorPageCount(prefixBytes)
    val firstCount = if (chunk > 0) {
      if (rustCount < chunk) { rustCount } else { chunk }
    } else {
      rustCount
    }
    val first = pagePrefix(firstCount)
    // Subsequent chunks are correctly pinned to the first response revision in
    // the implementation, but they still stop at rustCount, not expectedCount.
    val allRequested = pagePrefix(rustCount)
    val fetched = allRequested
    all {
      prefixBytes.in(LENGTHS),
      chunk.in(CHUNK_PAGES),
      prefixLength' = prefixBytes,
      chunkPages' = chunk,
      firstSelector' = first,
      rustFetched' = fetched,
      expectedFetched' = pagePrefix(expectedCount),
      chunkRequestsPinned' = true,
      didBootstrap' = true,
    }
  }

  run reproSubPagePrefixRequestsNoPages =
    init
      .then(bootstrapPrefixFor(1, 0))
      .expect(expectedFetched == Set(0))
      .expect(firstSelector == Set())
      .expect(rustFetched == Set())
      .expect(not(ExactPrefixFetch))

  run reproNonAlignedPrefixMissesLastPage =
    init
      .then(bootstrapPrefixFor(5, 0))
      .expect(expectedFetched == Set(0, 1))
      .expect(rustFetched == Set(0))
      .expect(not(PrefixCoverage))

  run reproChunkedNonAlignedPrefixMissesLastPage =
    init
      .then(bootstrapPrefixFor(9, 1))
      .expect(expectedFetched == Set(0, 1, 2))
      .expect(rustFetched == Set(0, 1))
      .expect(chunkRequestsPinned)
      .expect(not(PrefixCoverage))

  run reproPageAlignedPrefixMatches =
    init
      .then(bootstrapPrefixFor(8, 1))
      .expect(expectedFetched == Set(0, 1))
      .expect(rustFetched == expectedFetched)
      .expect(ExactPrefixFetch)

  action step = any {
    bootstrapPrefix,
  }

  pure def TypeOK: bool =
    and {
      prefixLength.in(LENGTHS.union(Set(NO_LENGTH))),
      chunkPages.in(CHUNK_PAGES),
      firstSelector.subseteq(PAGES),
      rustFetched.subseteq(PAGES),
      expectedFetched.subseteq(PAGES),
    }

  pure def RustSelectorShape: bool =
    not(didBootstrap) or
      rustFetched == pagePrefix(rustFloorPageCount(prefixLength))

  pure def PrefixCoverage: bool =
    expectedFetched.subseteq(rustFetched)

  pure def NoOverFetchBeyondPrefix: bool =
    rustFetched.subseteq(expectedFetched)

  pure def ExactPrefixFetch: bool =
    rustFetched == expectedFetched

  temporal spec = init.and(always(step.orKeep(
    (
      prefixLength,
      chunkPages,
      firstSelector,
      rustFetched,
      expectedFetched,
      chunkRequestsPinned,
      didBootstrap
    )
  )))
}
