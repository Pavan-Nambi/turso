module turso_sync_dirty_clean_failures {
  pure val OLD: int = 0
  pure val NEW1: int = 1
  pure val NEW2: int = 2
  pure val PARTIAL: int = 3
  pure val NO_VALUE: int = -1
  pure val VALUES: Set[int] = Set(OLD, NEW1, NEW2, PARTIAL, NO_VALUE)

  pure val NONE: int = 0
  pure val CLEAN: int = 1
  pure val REMOTE: int = 2
  pure val EOF: int = 3
  pure val READ_SOURCES: Set[int] = Set(NONE, CLEAN, REMOTE, EOF)

  pure val NO_PAGE: int = 0
  pure val PAGES: Set[int] = Set(1, 2)
  pure val LENGTHS: Set[int] = Set(0, 1, 2)
  pure val NO_TRUNCATE: int = -1

  var hasDirty: bool
  var asyncBackend: bool
  var permissiveShortOk: bool

  var cleanFilePages: int
  var dirtyFilePages: int
  var cleanHole: int -> bool
  var dirtyHole: int -> bool
  var cleanValue: int -> int
  var dirtyValue: int -> int

  // Ghost certificate: true exactly when the clean bytes are justified by a
  // completed full clean-file operation or by initial equal clean/dirty state.
  var cleanTrust: int -> bool

  var pendingCleanWrite: int -> bool
  var pendingValue: int -> int
  var failedCleanWrites: Set[int]
  var shortCleanWrites: Set[int]

  var pendingTruncate: bool
  var pendingTruncateLen: int
  var completedTruncateLen: int
  var failedCleanTruncate: bool

  var lastReadPage: int
  var lastReadSource: int
  var lastReadValue: int
  var allReadDecisionsMatched: bool

  pure val oldByPage: int -> int =
    PAGES.mapBy(_ => OLD)

  pure val falseByPage: int -> bool =
    PAGES.mapBy(_ => false)

  pure val trueByPage: int -> bool =
    PAGES.mapBy(_ => true)

  pure val noPendingValueByPage: int -> int =
    PAGES.mapBy(_ => NO_VALUE)

  action initNoDirtySync = initWith(false, false, false)
  action initDirtySync = initWith(true, false, false)
  action initDirtyAsync = initWith(true, true, false)
  action initDirtyAsyncPermissiveShort = initWith(true, true, true)

  action initWith(configHasDirty: bool, configAsync: bool, configShortOk: bool): bool = all {
    hasDirty' = configHasDirty,
    asyncBackend' = configAsync,
    permissiveShortOk' = configShortOk,
    cleanFilePages' = 2,
    dirtyFilePages' = if (configHasDirty) { 2 } else { 0 },
    cleanHole' = PAGES.mapBy(_ => false),
    dirtyHole' = PAGES.mapBy(_ => false),
    cleanValue' = oldByPage,
    dirtyValue' = oldByPage,
    cleanTrust' = if (configHasDirty) { trueByPage } else { falseByPage },
    pendingCleanWrite' = falseByPage,
    pendingValue' = noPendingValueByPage,
    failedCleanWrites' = Set(),
    shortCleanWrites' = Set(),
    pendingTruncate' = false,
    pendingTruncateLen' = NO_TRUNCATE,
    completedTruncateLen' = NO_TRUNCATE,
    failedCleanTruncate' = false,
    lastReadPage' = NO_PAGE,
    lastReadSource' = NONE,
    lastReadValue' = NO_VALUE,
    allReadDecisionsMatched' = true,
  }

  action init = any {
    initNoDirtySync,
    initDirtySync,
    initDirtyAsync,
    initDirtyAsyncPermissiveShort,
  }

  action keepConfig = all {
    hasDirty' = hasDirty,
    asyncBackend' = asyncBackend,
    permissiveShortOk' = permissiveShortOk,
  }

  action keepFiles = all {
    cleanFilePages' = cleanFilePages,
    dirtyFilePages' = dirtyFilePages,
    cleanHole' = cleanHole,
    dirtyHole' = dirtyHole,
    cleanValue' = cleanValue,
    dirtyValue' = dirtyValue,
    cleanTrust' = cleanTrust,
  }

  action keepWriteState = all {
    pendingCleanWrite' = pendingCleanWrite,
    pendingValue' = pendingValue,
    failedCleanWrites' = failedCleanWrites,
    shortCleanWrites' = shortCleanWrites,
  }

  action keepTruncateState = all {
    pendingTruncate' = pendingTruncate,
    pendingTruncateLen' = pendingTruncateLen,
    completedTruncateLen' = completedTruncateLen,
    failedCleanTruncate' = failedCleanTruncate,
  }

  action keepLastRead = all {
    lastReadPage' = lastReadPage,
    lastReadSource' = lastReadSource,
    lastReadValue' = lastReadValue,
    allReadDecisionsMatched' = allReadDecisionsMatched,
  }

  action recordRead(p: int, source: int, value: int): bool = all {
    lastReadPage' = p,
    lastReadSource' = source,
    lastReadValue' = value,
    allReadDecisionsMatched' = allReadDecisionsMatched,
  }

  action readPage = {
    nondet p = PAGES.oneOf()
    readPageAt(p)
  }

  action readPageAt(p: int): bool = all {
    p.in(PAGES),
    keepConfig,
    keepFiles,
    keepWriteState,
    keepTruncateState,
    if (p > cleanFilePages) {
      recordRead(p, EOF, NO_VALUE)
    } else if (cleanHole.get(p)) {
      recordRead(p, REMOTE, NEW2)
    } else if (not(hasDirty)) {
      recordRead(p, CLEAN, cleanValue.get(p))
    } else if (dirtyHole.get(p)) {
      recordRead(p, CLEAN, cleanValue.get(p))
    } else if (dirtyValue.get(p) == cleanValue.get(p)) {
      recordRead(p, CLEAN, cleanValue.get(p))
    } else {
      recordRead(p, REMOTE, NEW2)
    },
  }

  action writeStart = {
    nondet p = PAGES.oneOf()
    nondet v = Set(NEW1, NEW2).oneOf()
    writeStartAt(p, v)
  }

  action writeStartAt(p: int, v: int): bool = all {
    p.in(PAGES),
    v.in(Set(NEW1, NEW2)),
    asyncBackend,
    not(pendingCleanWrite.get(p)),
    keepConfig,
    cleanFilePages' = cleanFilePages,
    dirtyFilePages' = dirtyFilePages,
    cleanHole' = cleanHole,
    dirtyHole' = if (hasDirty) { dirtyHole.set(p, true) } else { dirtyHole },
    cleanValue' = cleanValue,
    dirtyValue' = dirtyValue,
    cleanTrust' = if (hasDirty) { cleanTrust.set(p, false) } else { cleanTrust },
    pendingCleanWrite' = pendingCleanWrite.set(p, true),
    pendingValue' = pendingValue.set(p, v),
    failedCleanWrites' = failedCleanWrites,
    shortCleanWrites' = shortCleanWrites,
    keepTruncateState,
    keepLastRead,
  }

  action writeCallErrAfterDirtyPunch = {
    nondet p = PAGES.oneOf()
    nondet v = Set(NEW1, NEW2).oneOf()
    writeCallErrAfterDirtyPunchAt(p, v)
  }

  action writeCallErrAfterDirtyPunchAt(p: int, v: int): bool = all {
    p.in(PAGES),
    v.in(Set(NEW1, NEW2)),
    asyncBackend,
    not(pendingCleanWrite.get(p)),
    keepConfig,
    cleanFilePages' = cleanFilePages,
    dirtyFilePages' = dirtyFilePages,
    cleanHole' = cleanHole,
    dirtyHole' = if (hasDirty) { dirtyHole.set(p, true) } else { dirtyHole },
    cleanValue' = cleanValue,
    dirtyValue' = dirtyValue,
    cleanTrust' = if (hasDirty) { cleanTrust.set(p, false) } else { cleanTrust },
    pendingCleanWrite' = pendingCleanWrite,
    pendingValue' = pendingValue,
    failedCleanWrites' = failedCleanWrites.union(Set(p)),
    shortCleanWrites' = shortCleanWrites,
    keepTruncateState,
    keepLastRead,
  }

  action writeCompleteOkFull = {
    nondet p = PAGES.oneOf()
    writeCompleteOkFullAt(p)
  }

  action writeCompleteOkFullAt(p: int): bool = all {
    p.in(PAGES),
    pendingCleanWrite.get(p),
    keepConfig,
    cleanFilePages' = if (p > cleanFilePages) { p } else { cleanFilePages },
    dirtyFilePages' = dirtyFilePages,
    cleanHole' = cleanHole.set(p, false),
    dirtyHole' = dirtyHole,
    cleanValue' = cleanValue.set(p, pendingValue.get(p)),
    dirtyValue' = dirtyValue,
    cleanTrust' = if (hasDirty) { cleanTrust.set(p, true) } else { cleanTrust },
    pendingCleanWrite' = pendingCleanWrite.set(p, false),
    pendingValue' = pendingValue.set(p, NO_VALUE),
    failedCleanWrites' = failedCleanWrites,
    shortCleanWrites' = shortCleanWrites,
    keepTruncateState,
    keepLastRead,
  }

  action writeCompleteErr = {
    nondet p = PAGES.oneOf()
    writeCompleteErrAt(p)
  }

  action writeCompleteErrAt(p: int): bool = all {
    p.in(PAGES),
    pendingCleanWrite.get(p),
    keepConfig,
    keepFiles,
    pendingCleanWrite' = pendingCleanWrite.set(p, false),
    pendingValue' = pendingValue.set(p, NO_VALUE),
    failedCleanWrites' = failedCleanWrites.union(Set(p)),
    shortCleanWrites' = shortCleanWrites,
    keepTruncateState,
    keepLastRead,
  }

  action writeCompleteOkShort = {
    nondet p = PAGES.oneOf()
    writeCompleteOkShortAt(p)
  }

  action writeCompleteOkShortAt(p: int): bool = all {
    p.in(PAGES),
    pendingCleanWrite.get(p),
    permissiveShortOk,
    keepConfig,
    cleanFilePages' = if (p > cleanFilePages) { p } else { cleanFilePages },
    dirtyFilePages' = dirtyFilePages,
    cleanHole' = cleanHole.set(p, false),
    dirtyHole' = dirtyHole,
    cleanValue' = cleanValue.set(p, PARTIAL),
    dirtyValue' = dirtyValue,
    cleanTrust' = if (hasDirty) { cleanTrust.set(p, false) } else { cleanTrust },
    pendingCleanWrite' = pendingCleanWrite.set(p, false),
    pendingValue' = pendingValue.set(p, NO_VALUE),
    failedCleanWrites' = failedCleanWrites,
    shortCleanWrites' = shortCleanWrites.union(Set(p)),
    keepTruncateState,
    keepLastRead,
  }

  action writePagesStart = all {
    asyncBackend,
    not(pendingCleanWrite.get(1)),
    not(pendingCleanWrite.get(2)),
    keepConfig,
    cleanFilePages' = cleanFilePages,
    dirtyFilePages' = dirtyFilePages,
    cleanHole' = cleanHole,
    dirtyHole' = if (hasDirty) {
      dirtyHole.set(1, true).set(2, true)
    } else {
      dirtyHole
    },
    cleanValue' = cleanValue,
    dirtyValue' = dirtyValue,
    cleanTrust' = if (hasDirty) {
      cleanTrust.set(1, false).set(2, false)
    } else {
      cleanTrust
    },
    pendingCleanWrite' = pendingCleanWrite.set(1, true).set(2, true),
    pendingValue' = pendingValue.set(1, NEW1).set(2, NEW2),
    failedCleanWrites' = failedCleanWrites,
    shortCleanWrites' = shortCleanWrites,
    keepTruncateState,
    keepLastRead,
  }

  action writePagesCompleteErrAfterPrefix = all {
    pendingCleanWrite.get(1),
    pendingCleanWrite.get(2),
    keepConfig,
    cleanFilePages' = cleanFilePages,
    dirtyFilePages' = dirtyFilePages,
    cleanHole' = cleanHole.set(1, false),
    dirtyHole' = dirtyHole,
    // Physical prefix may have reached page 1 before aggregate pwritev failed.
    cleanValue' = cleanValue.set(1, pendingValue.get(1)),
    dirtyValue' = dirtyValue,
    cleanTrust' = if (hasDirty) {
      cleanTrust.set(1, false).set(2, false)
    } else {
      cleanTrust
    },
    pendingCleanWrite' = pendingCleanWrite.set(1, false).set(2, false),
    pendingValue' = pendingValue.set(1, NO_VALUE).set(2, NO_VALUE),
    failedCleanWrites' = failedCleanWrites.union(Set(1, 2)),
    shortCleanWrites' = shortCleanWrites,
    keepTruncateState,
    keepLastRead,
  }

  action makePageUntrusted = {
    nondet p = PAGES.oneOf()
    makePageUntrustedAt(p)
  }

  action makePageUntrustedAt(p: int): bool = all {
    p.in(PAGES),
    hasDirty,
    p <= cleanFilePages,
    keepConfig,
    cleanFilePages' = cleanFilePages,
    dirtyFilePages' = dirtyFilePages,
    cleanHole' = cleanHole,
    dirtyHole' = dirtyHole.set(p, false),
    cleanValue' = cleanValue.set(p, OLD),
    dirtyValue' = dirtyValue.set(p, NEW1),
    cleanTrust' = cleanTrust.set(p, false),
    keepWriteState,
    keepTruncateState,
    keepLastRead,
  }

  action truncateStart = {
    nondet len = Set(0, 1).oneOf()
    truncateStartTo(len)
  }

  action truncateStartTo(len: int): bool = all {
    len.in(Set(0, 1)),
    hasDirty,
    asyncBackend,
    not(pendingTruncate),
    keepConfig,
    cleanFilePages' = cleanFilePages,
    dirtyFilePages' = len,
    cleanHole' = cleanHole,
    dirtyHole' = PAGES.mapBy(p => if (p > len) { true } else { dirtyHole.get(p) }),
    cleanValue' = cleanValue,
    dirtyValue' = dirtyValue,
    cleanTrust' = PAGES.mapBy(p => if (p > len) { false } else { cleanTrust.get(p) }),
    keepWriteState,
    pendingTruncate' = true,
    pendingTruncateLen' = len,
    completedTruncateLen' = completedTruncateLen,
    failedCleanTruncate' = failedCleanTruncate,
    keepLastRead,
  }

  action truncateCallErrAfterDirtyTruncate = {
    nondet len = Set(0, 1).oneOf()
    truncateCallErrAfterDirtyTruncateTo(len)
  }

  action truncateCallErrAfterDirtyTruncateTo(len: int): bool = all {
    len.in(Set(0, 1)),
    hasDirty,
    asyncBackend,
    not(pendingTruncate),
    keepConfig,
    cleanFilePages' = cleanFilePages,
    dirtyFilePages' = len,
    cleanHole' = cleanHole,
    dirtyHole' = PAGES.mapBy(p => if (p > len) { true } else { dirtyHole.get(p) }),
    cleanValue' = cleanValue,
    dirtyValue' = dirtyValue,
    cleanTrust' = PAGES.mapBy(p => if (p > len) { false } else { cleanTrust.get(p) }),
    keepWriteState,
    pendingTruncate' = false,
    pendingTruncateLen' = NO_TRUNCATE,
    completedTruncateLen' = completedTruncateLen,
    failedCleanTruncate' = true,
    keepLastRead,
  }

  action truncateCompleteOk = all {
    pendingTruncate,
    keepConfig,
    cleanFilePages' = pendingTruncateLen,
    dirtyFilePages' = dirtyFilePages,
    cleanHole' = PAGES.mapBy(p => if (p > pendingTruncateLen) { true } else { cleanHole.get(p) }),
    dirtyHole' = dirtyHole,
    cleanValue' = cleanValue,
    dirtyValue' = dirtyValue,
    cleanTrust' = PAGES.mapBy(p => if (p > pendingTruncateLen) { false } else { cleanTrust.get(p) }),
    keepWriteState,
    pendingTruncate' = false,
    pendingTruncateLen' = NO_TRUNCATE,
    completedTruncateLen' = pendingTruncateLen,
    failedCleanTruncate' = failedCleanTruncate,
    keepLastRead,
  }

  action truncateCompleteErr = all {
    pendingTruncate,
    keepConfig,
    keepFiles,
    keepWriteState,
    pendingTruncate' = false,
    pendingTruncateLen' = NO_TRUNCATE,
    completedTruncateLen' = completedTruncateLen,
    failedCleanTruncate' = true,
    keepLastRead,
  }

  run reproWriteErrorAfterDirtyPunchLeavesOldCleanTrusted =
    initDirtyAsync
      .then(writeStartAt(1, NEW1))
      .then(writeCompleteErrAt(1))
      .expect(failedCleanWrites.contains(1))
      .expect(dirtyHole.get(1))
      .expect(not(FailedCleanWriteDoesNotLeaveTrustedDirtyHole))
      .then(readPageAt(1))
      .expect(lastReadSource == CLEAN)
      .expect(lastReadValue == OLD)
      .expect(not(DirtyHoleFastPathRequiresCleanCertificate))

  run reproDirectWriteCallErrorAfterDirtyPunchLeavesOldCleanTrusted =
    initDirtyAsync
      .then(writeCallErrAfterDirtyPunchAt(1, NEW1))
      .expect(failedCleanWrites.contains(1))
      .expect(dirtyHole.get(1))
      .then(readPageAt(1))
      .expect(lastReadSource == CLEAN)
      .expect(lastReadValue == OLD)
      .expect(not(FailedCleanWriteDoesNotLeaveTrustedDirtyHole))

  run reproShortWriteAfterDirtyPunchLeavesPartialCleanTrusted =
    initDirtyAsyncPermissiveShort
      .then(writeStartAt(1, NEW1))
      .then(writeCompleteOkShortAt(1))
      .expect(shortCleanWrites.contains(1))
      .then(readPageAt(1))
      .expect(lastReadSource == CLEAN)
      .expect(lastReadValue == PARTIAL)
      .expect(not(ShortCleanWriteDoesNotCertifyFullPageOrAdvanceVisibleSize))

  run reproWritePagesErrorLeavesSecondPageTrusted =
    initDirtyAsync
      .then(writePagesStart)
      .then(writePagesCompleteErrAfterPrefix)
      .expect(failedCleanWrites.contains(2))
      .then(readPageAt(2))
      .expect(lastReadSource == CLEAN)
      .expect(lastReadValue == OLD)
      .expect(not(FailedCleanWriteDoesNotLeaveTrustedDirtyHole))

  run reproDirtyTruncateThenCleanTruncateErrorLeavesDroppedPageReadable =
    initDirtyAsync
      .then(makePageUntrustedAt(2))
      .then(truncateStartTo(1))
      .expect(pendingTruncate)
      .expect(dirtyHole.get(2))
      .expect(not(DirtyTruncateCannotEraseShadowBeforeCleanTruncateCommits))
      .then(truncateCompleteErr)
      .then(readPageAt(2))
      .expect(lastReadSource == CLEAN)
      .expect(lastReadValue == OLD)

  run reproDirectTruncateCallErrorLeavesDroppedPageReadable =
    initDirtyAsync
      .then(makePageUntrustedAt(2))
      .then(truncateCallErrAfterDirtyTruncateTo(1))
      .expect(failedCleanTruncate)
      .then(readPageAt(2))
      .expect(lastReadSource == CLEAN)
      .expect(lastReadValue == OLD)

  run reproPendingWriteCompletionReexpandsAfterTruncate =
    initDirtyAsync
      .then(writeStartAt(2, NEW2))
      .then(truncateStartTo(1))
      .then(truncateCompleteOk)
      .expect(cleanFilePages == 1)
      .then(writeCompleteOkFullAt(2))
      .expect(cleanFilePages == 2)
      .expect(not(CompletedTruncateDominatesOlderWriteCompletions))

  run reproFullWriteCertifiesDirtyHole =
    initDirtyAsync
      .then(writeStartAt(1, NEW1))
      .then(writeCompleteOkFullAt(1))
      .expect(dirtyHole.get(1))
      .expect(cleanTrust.get(1))
      .then(readPageAt(1))
      .expect(lastReadSource == CLEAN)
      .expect(lastReadValue == NEW1)

  run reproNoDirtyFileNoShadowTrust =
    initNoDirtySync
      .then(readPageAt(1))
      .expect(lastReadSource == CLEAN)
      .expect(NoDirtyFileNoShadowTrust)

  action step = any {
    readPage,
    writeStart,
    writeCallErrAfterDirtyPunch,
    writeCompleteOkFull,
    writeCompleteErr,
    writeCompleteOkShort,
    writePagesStart,
    writePagesCompleteErrAfterPrefix,
    makePageUntrusted,
    truncateStart,
    truncateCallErrAfterDirtyTruncate,
    truncateCompleteOk,
    truncateCompleteErr,
  }

  pure def TypeOK: bool =
    and {
      cleanFilePages.in(LENGTHS),
      dirtyFilePages.in(LENGTHS),
      pendingTruncateLen.in(LENGTHS.union(Set(NO_TRUNCATE))),
      completedTruncateLen.in(LENGTHS.union(Set(NO_TRUNCATE))),
      cleanHole.keys() == PAGES,
      dirtyHole.keys() == PAGES,
      cleanValue.keys() == PAGES,
      dirtyValue.keys() == PAGES,
      cleanTrust.keys() == PAGES,
      pendingCleanWrite.keys() == PAGES,
      pendingValue.keys() == PAGES,
      failedCleanWrites.subseteq(PAGES),
      shortCleanWrites.subseteq(PAGES),
      PAGES.forall(p =>
        and {
          cleanValue.get(p).in(VALUES),
          dirtyValue.get(p).in(VALUES),
          pendingValue.get(p).in(VALUES),
          pendingCleanWrite.get(p) or pendingValue.get(p) == NO_VALUE,
        }
      ),
      not(hasDirty) implies dirtyFilePages == 0,
      lastReadPage.in(PAGES.union(Set(NO_PAGE))),
      lastReadSource.in(READ_SOURCES),
      lastReadValue.in(VALUES),
      allReadDecisionsMatched,
    }

  pure def ReadDecisionMatchesLazyStorage: bool =
    allReadDecisionsMatched

  pure def NoDirtyFileNoShadowTrust: bool =
    not(hasDirty) implies and {
      dirtyFilePages == 0,
      PAGES.forall(p => not(dirtyHole.get(p)) and not(cleanTrust.get(p))),
    }

  pure def DirtyHoleFastPathRequiresCleanCertificate: bool =
    PAGES.forall(p =>
      not(hasDirty) or
        p > cleanFilePages or
        not(dirtyHole.get(p)) or
        cleanTrust.get(p)
    )

  pure def FailedCleanWriteDoesNotLeaveTrustedDirtyHole: bool =
    failedCleanWrites.forall(p =>
      p > cleanFilePages or not(dirtyHole.get(p))
    )

  pure def ShortCleanWriteDoesNotCertifyFullPageOrAdvanceVisibleSize: bool =
    shortCleanWrites.forall(p =>
      and {
        p > cleanFilePages or not(dirtyHole.get(p)),
        cleanValue.get(p) != PARTIAL,
      }
    )

  pure def DirtyTruncateCannotEraseShadowBeforeCleanTruncateCommits: bool =
    not(pendingTruncate) or
      PAGES.forall(p =>
        p <= pendingTruncateLen or
          p > cleanFilePages or
          not(dirtyHole.get(p))
      )

  pure def CompletedTruncateDominatesOlderWriteCompletions: bool =
    completedTruncateLen == NO_TRUNCATE or cleanFilePages <= completedTruncateLen

  temporal spec = init.and(always(step.orKeep(
    (
      hasDirty,
      asyncBackend,
      permissiveShortOk,
      cleanFilePages,
      dirtyFilePages,
      cleanHole,
      dirtyHole,
      cleanValue,
      dirtyValue,
      cleanTrust,
      pendingCleanWrite,
      pendingValue,
      failedCleanWrites,
      shortCleanWrites,
      pendingTruncate,
      pendingTruncateLen,
      completedTruncateLen,
      failedCleanTruncate,
      lastReadPage,
      lastReadSource,
      lastReadValue,
      allReadDecisionsMatched
    )
  )))
}
