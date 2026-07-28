// Generates bounded MVCC histories with setup, an optional pinned reader,
// one concurrent writer, row/schema mutations, commit/rollback, and PASSIVE
// checkpoints. It tracks committed, writer-private, and reader-snapshot state;
// Safety checks isolation, transaction outcomes, and state validity.
module mvcc_semantic_programs {
  type Slot = {
    present: bool,
    value: int,
  }

  type TableState = {
    exists: bool,
    row0: Slot,
    row1: Slot,
  }

  type ModelState = {
    phase: str,
    committed0: TableState,
    committed1: TableState,
    pending0: TableState,
    pending1: TableState,
    snapshot0: TableState,
    snapshot1: TableState,
    readerPinned: bool,
    setupCommands: int,
    writerCommands: int,
    concurrentCheckpoints: int,
    writerOpen: bool,
    writerOutcome: str,
  }

  val Setup = "setup"
  val Concurrent = "concurrent"
  val Done = "done"
  val Open = "open"
  val Commit = "commit"
  val Rollback = "rollback"

  val Tables = Set(0, 1)
  val Keys = Set(0, 1)
  val Values = Set(10, 20, 30)
  val MaxSetupCommands = 5
  val MaxWriterCommands = 4
  val MaxConcurrentCheckpoints = 2

  val EmptySlot: Slot = {
    present: false,
    value: 0,
  }

  val EmptyTable: TableState = {
    exists: false,
    row0: EmptySlot,
    row1: EmptySlot,
  }

  pure def slotAt(table: TableState, key: int): Slot =
    if (key == 0) table.row0 else table.row1

  pure def validSlot(slot: Slot): bool =
    not(slot.present) or Values.contains(slot.value)

  pure def validTable(table: TableState): bool =
    validSlot(table.row0)
      and validSlot(table.row1)
      and (
        table.exists
          or (not(table.row0.present) and not(table.row1.present))
      )

  pure def createTable(_prior: TableState): TableState = {
    ...EmptyTable,
    exists: true,
  }

  pure def dropTable(_prior: TableState): TableState = EmptyTable

  pure def putRow(
    table: TableState,
    key: int,
    value: int,
  ): TableState =
    if (key == 0) {
      ...table,
      row0: { present: true, value: value },
    } else {
      ...table,
      row1: { present: true, value: value },
    }

  pure def deleteRow(table: TableState, key: int): TableState =
    if (key == 0) {
      ...table,
      row0: EmptySlot,
    } else {
      ...table,
      row1: EmptySlot,
    }

  var model: ModelState

  action init = {
    model' = {
      phase: Setup,
      committed0: EmptyTable,
      committed1: EmptyTable,
      pending0: EmptyTable,
      pending1: EmptyTable,
      snapshot0: EmptyTable,
      snapshot1: EmptyTable,
      readerPinned: false,
      setupCommands: 0,
      writerCommands: 0,
      concurrentCheckpoints: 0,
      writerOpen: false,
      writerOutcome: Open,
    }
  }

  action SetupCreate = {
    nondet table = Tables.oneOf()
    all {
      model.phase == Setup,
      model.setupCommands < MaxSetupCommands,
      if (table == 0) not(model.committed0.exists) else not(model.committed1.exists),
      model' = {
        ...model,
        committed0:
          if (table == 0) createTable(model.committed0) else model.committed0,
        committed1:
          if (table == 1) createTable(model.committed1) else model.committed1,
        setupCommands: model.setupCommands + 1,
      },
    }
  }

  action SetupPut = {
    nondet table = Tables.oneOf()
    nondet key = Keys.oneOf()
    nondet value = Values.oneOf()
    all {
      model.phase == Setup,
      model.setupCommands > 0,
      model.setupCommands < MaxSetupCommands,
      if (table == 0) model.committed0.exists else model.committed1.exists,
      not(
        slotAt(if (table == 0) model.committed0 else model.committed1, key).present
          and slotAt(
            if (table == 0) model.committed0 else model.committed1,
            key,
          ).value == value
      ),
      model' = {
        ...model,
        committed0:
          if (table == 0) putRow(model.committed0, key, value) else model.committed0,
        committed1:
          if (table == 1) putRow(model.committed1, key, value) else model.committed1,
        setupCommands: model.setupCommands + 1,
      },
    }
  }

  action SetupDelete = {
    nondet table = Tables.oneOf()
    nondet key = Keys.oneOf()
    all {
      model.phase == Setup,
      model.setupCommands > 0,
      model.setupCommands < MaxSetupCommands,
      if (table == 0) model.committed0.exists else model.committed1.exists,
      slotAt(if (table == 0) model.committed0 else model.committed1, key).present,
      model' = {
        ...model,
        committed0:
          if (table == 0) deleteRow(model.committed0, key) else model.committed0,
        committed1:
          if (table == 1) deleteRow(model.committed1, key) else model.committed1,
        setupCommands: model.setupCommands + 1,
      },
    }
  }

  action SetupCheckpoint = all {
    model.phase == Setup,
    model.setupCommands > 0,
    model.setupCommands < MaxSetupCommands,
    model.committed0.exists or model.committed1.exists,
    model' = {
      ...model,
      setupCommands: model.setupCommands + 1,
    },
  }

  action BeginConcurrent = {
    nondet pinReader = Set(true, false).oneOf()
    all {
      model.phase == Setup,
      model.setupCommands > 0,
      model.committed0.exists or model.committed1.exists,
      model' = {
        ...model,
        phase: Concurrent,
        pending0: model.committed0,
        pending1: model.committed1,
        snapshot0: model.committed0,
        snapshot1: model.committed1,
        readerPinned: pinReader,
        writerOpen: true,
        writerOutcome: Open,
      },
    }
  }

  action WriterPut = {
    nondet table = Tables.oneOf()
    nondet key = Keys.oneOf()
    nondet value = Values.oneOf()
    all {
      model.phase == Concurrent,
      model.writerOpen,
      model.writerCommands < MaxWriterCommands,
      if (table == 0) model.pending0.exists else model.pending1.exists,
      not(
        slotAt(if (table == 0) model.pending0 else model.pending1, key).present
          and slotAt(
            if (table == 0) model.pending0 else model.pending1,
            key,
          ).value == value
      ),
      model' = {
        ...model,
        pending0:
          if (table == 0) putRow(model.pending0, key, value) else model.pending0,
        pending1:
          if (table == 1) putRow(model.pending1, key, value) else model.pending1,
        writerCommands: model.writerCommands + 1,
      },
    }
  }

  action WriterDelete = {
    nondet table = Tables.oneOf()
    nondet key = Keys.oneOf()
    all {
      model.phase == Concurrent,
      model.writerOpen,
      model.writerCommands < MaxWriterCommands,
      if (table == 0) model.pending0.exists else model.pending1.exists,
      slotAt(if (table == 0) model.pending0 else model.pending1, key).present,
      model' = {
        ...model,
        pending0:
          if (table == 0) deleteRow(model.pending0, key) else model.pending0,
        pending1:
          if (table == 1) deleteRow(model.pending1, key) else model.pending1,
        writerCommands: model.writerCommands + 1,
      },
    }
  }

  action WriterDrop = {
    nondet table = Tables.oneOf()
    all {
      model.phase == Concurrent,
      model.writerOpen,
      model.writerCommands < MaxWriterCommands,
      if (table == 0) model.pending0.exists else model.pending1.exists,
      model' = {
        ...model,
        pending0:
          if (table == 0) dropTable(model.pending0) else model.pending0,
        pending1:
          if (table == 1) dropTable(model.pending1) else model.pending1,
        writerCommands: model.writerCommands + 1,
      },
    }
  }

  action WriterCreate = {
    nondet table = Tables.oneOf()
    all {
      model.phase == Concurrent,
      model.writerOpen,
      model.writerCommands < MaxWriterCommands,
      if (table == 0) not(model.pending0.exists) else not(model.pending1.exists),
      model' = {
        ...model,
        pending0:
          if (table == 0) createTable(model.pending0) else model.pending0,
        pending1:
          if (table == 1) createTable(model.pending1) else model.pending1,
        writerCommands: model.writerCommands + 1,
      },
    }
  }

  action WriterCommit = all {
    model.phase == Concurrent,
    model.writerOpen,
    model.writerCommands > 0,
    model' = {
      ...model,
      committed0: model.pending0,
      committed1: model.pending1,
      writerOpen: false,
      writerOutcome: Commit,
    },
  }

  action WriterRollback = all {
    model.phase == Concurrent,
    model.writerOpen,
    model.writerCommands > 0,
    model' = {
      ...model,
      writerOpen: false,
      writerOutcome: Rollback,
    },
  }

  action ConcurrentCheckpoint = all {
    model.phase == Concurrent,
    model.concurrentCheckpoints < MaxConcurrentCheckpoints,
    model' = {
      ...model,
      concurrentCheckpoints: model.concurrentCheckpoints + 1,
    },
  }

  action EndConcurrent = all {
    model.phase == Concurrent,
    not(model.writerOpen),
    model.concurrentCheckpoints > 0,
    model' = {
      ...model,
      phase: Done,
    },
  }

  action DoneStutter = all {
    model.phase == Done,
    model' = model,
  }

  action step = any {
    SetupCreate,
    SetupPut,
    SetupDelete,
    SetupCheckpoint,
    BeginConcurrent,
    WriterPut,
    WriterDelete,
    WriterDrop,
    WriterCreate,
    WriterCommit,
    WriterRollback,
    ConcurrentCheckpoint,
    EndConcurrent,
    DoneStutter,
  }

  val CommittedStateStableWhileWriterOpen =
    model.phase != Concurrent
      or not(model.writerOpen)
      or (
        model.committed0 == model.snapshot0
          and model.committed1 == model.snapshot1
      )

  val RollbackRestoresSnapshot =
    model.writerOutcome != Rollback
      or (
        model.committed0 == model.snapshot0
          and model.committed1 == model.snapshot1
      )

  val CommitPublishesPendingState =
    model.writerOutcome != Commit
      or (
        model.committed0 == model.pending0
          and model.committed1 == model.pending1
      )

  val CompletedTransactionClosed =
    model.phase != Done
      or (
        not(model.writerOpen)
          and (
            model.writerOutcome == Commit
              or model.writerOutcome == Rollback
          )
      )

  val Safety =
    validTable(model.committed0)
      and validTable(model.committed1)
      and validTable(model.pending0)
      and validTable(model.pending1)
      and validTable(model.snapshot0)
      and validTable(model.snapshot1)
      and model.setupCommands >= 0
      and model.setupCommands <= MaxSetupCommands
      and model.writerCommands >= 0
      and model.writerCommands <= MaxWriterCommands
      and model.concurrentCheckpoints >= 0
      and model.concurrentCheckpoints <= MaxConcurrentCheckpoints
      and CommittedStateStableWhileWriterOpen
      and RollbackRestoresSnapshot
      and CommitPublishesPendingState
      and CompletedTransactionClosed

  val CampaignComplete = model.phase == Done
}
