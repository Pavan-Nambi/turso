module turso_sync_transform_connect_repro {
  var pc: int

  action init = pc' = 0

  action localSkipId1 = all {
    pc == 0,
    pc' = 1,
  }

  action push = all {
    pc.in(Set(1, 4)),
    pc' = if (pc == 1) { 2 } else { 5 },
  }

  action expectSkipId1Retried = all {
    pc == 2,
    pc' = 3,
  }

  action localKeepId2 = all {
    pc == 3,
    pc' = 4,
  }

  action expectSkipId1AckedByLaterKeep = all {
    pc == 5,
    pc' = 6,
  }

  action step = any {
    localSkipId1,
    push,
    expectSkipId1Retried,
    localKeepId2,
    expectSkipId1AckedByLaterKeep,
  }

  pure def TypeOK: bool = pc.in(0.to(6))

  temporal spec = init.and(always(step.orKeep(pc)))
}
