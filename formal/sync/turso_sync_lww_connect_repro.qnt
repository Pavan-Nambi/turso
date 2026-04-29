module turso_sync_lww_connect_repro {
  var pc: int

  action init = pc' = 0

  action clientADelete = all {
    pc == 0,
    pc' = 1,
  }

  action clientAPush = all {
    pc == 1,
    pc' = 2,
  }

  action clientBUpdate = all {
    pc == 2,
    pc' = 3,
  }

  action clientBPush = all {
    pc == 3,
    pc' = 4,
  }

  action expectLastPushWins = all {
    pc == 4,
    pc' = 5,
  }

  action step = any {
    clientADelete,
    clientAPush,
    clientBUpdate,
    clientBPush,
    expectLastPushWins,
  }

  pure def TypeOK: bool = pc.in(0.to(5))

  temporal spec = init.and(always(step.orKeep(pc)))
}
