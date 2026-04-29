module turso_sync_connect_repro {
  var pc: int

  action init = pc' = 0

  action applyRemoteRev1ThenResetRevert = all {
    pc == 0,
    pc' = 1,
  }

  action checkpointToMetadataBeforeMainTruncate = all {
    pc == 1,
    pc' = 2,
  }

  action crashRestartAfterCheckpointMeta = all {
    pc == 2,
    pc' = 3,
  }

  action applyRemoteRev2AfterCheckpointMetaCrash = all {
    pc == 3,
    pc' = 4,
  }

  action step = any {
    applyRemoteRev1ThenResetRevert,
    checkpointToMetadataBeforeMainTruncate,
    crashRestartAfterCheckpointMeta,
    applyRemoteRev2AfterCheckpointMetaCrash,
  }

  pure def TypeOK: bool = pc.in(0.to(4))

  temporal spec = init.and(always(step.orKeep(pc)))
}
