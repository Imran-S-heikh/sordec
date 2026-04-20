;; Soroban Annotated WAT
;; sections
;; type [10..30]
;; import [32..45]
;; function [47..53]
;; memory [55..58]
;; global [60..85]
;; export [87..134]
;; code [137..407]
;; custom:contractspecv0 [409..484]
;; custom:contractenvmetav0 [486..516]
;; custom:contractmetav0 [518..629]
;; imports
;; #0 i::0 func(type=0)
;; #1 i::_ func(type=0)
;; exports
;; memory -> Memory#0
;; add -> Func#3
;; _ -> Func#6
;; __data_end -> Global#1
;; __heap_base -> Global#2
;; interface
;; fn add(a: u64, b: u64) -> u64
;; contract metadata
;; rssdkver = 21.7.7#5da789c50b18a4c2be53394138212fed56f0dfc4
;; rsver = 1.91.1
;; environment: protocol=Some("21"), pre_release=Some("0")

(module
  (type (;0;) (func (param i64) (result i64)))
  (type (;1;) (func (param i32 i64)))
  (type (;2;) (func (param i64 i64) (result i64)))
  (type (;3;) (func))
  (import "i" "0" (func (;0;) (type 0)))
  (import "i" "_" (func (;1;) (type 0)))
  (memory (;0;) 16)
  (global (;0;) (mut i32) i32.const 1048576)
  (global (;1;) i32 i32.const 1048576)
  (global (;2;) i32 i32.const 1048576)
  (export "memory" (memory 0))
  (export "add" (func 3))
  (export "_" (func 6))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2))
  (func (;2;) (type 1) (param i32 i64)
    (local i32 i64)
    block ;; label = @1
      block ;; label = @2
        local.get 1
        i32.wrap_i64
        i32.const 255
        i32.and
        local.tee 2
        i32.const 64
        i32.eq
        br_if 0 (;@2;)
        block ;; label = @3
          local.get 2
          i32.const 6
          i32.eq
          br_if 0 (;@3;)
          i64.const 1
          local.set 3
          i64.const 34359740419
          local.set 1
          br 2 (;@1;)
        end
        local.get 1
        i64.const 8
        i64.shr_u
        local.set 1
        i64.const 0
        local.set 3
        br 1 (;@1;)
      end
      i64.const 0
      local.set 3
      local.get 1
      call 0
      local.set 1
    end
    local.get 0
    local.get 3
    i64.store
    local.get 0
    local.get 1
    i64.store offset=8
  )
  (func (;3;) (type 2) (param i64 i64) (result i64)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 2
    global.set 0
    local.get 2
    local.get 0
    call 2
    block ;; label = @1
      block ;; label = @2
        local.get 2
        i32.load
        i32.const 1
        i32.eq
        br_if 0 (;@2;)
        local.get 2
        i64.load offset=8
        local.set 0
        local.get 2
        local.get 1
        call 2
        local.get 2
        i32.load
        i32.const 1
        i32.eq
        br_if 0 (;@2;)
        local.get 2
        i64.load offset=8
        local.tee 1
        local.get 0
        i64.add
        local.tee 0
        local.get 1
        i64.lt_u
        br_if 1 (;@1;)
        block ;; label = @3
          block ;; label = @4
            local.get 0
            i64.const 72057594037927935
            i64.gt_u
            br_if 0 (;@4;)
            local.get 0
            i64.const 8
            i64.shl
            i64.const 6
            i64.or
            local.set 0
            br 1 (;@3;)
          end
          local.get 0
          call 1
          local.set 0
        end
        local.get 2
        i32.const 16
        i32.add
        global.set 0
        local.get 0
        return
      end
      unreachable
    end
    call 4
    unreachable
  )
  (func (;4;) (type 3)
    call 5
    unreachable
  )
  (func (;5;) (type 3)
    unreachable
  )
  (func (;6;) (type 3))
  (@custom "contractspecv0" (after code) "\00\00\00\00\00\00\00\00\00\00\00\03add\00\00\00\00\02\00\00\00\00\00\00\00\01a\00\00\00\00\00\00\06\00\00\00\00\00\00\00\01b\00\00\00\00\00\00\06\00\00\00\01\00\00\00\06")
  (@custom "contractenvmetav0" (after code) "\00\00\00\00\00\00\00\15\00\00\00\00")
  (@custom "contractmetav0" (after code) "\00\00\00\00\00\00\00\05rsver\00\00\00\00\00\00\061.91.1\00\00\00\00\00\00\00\00\00\08rssdkver\00\00\00/21.7.7#5da789c50b18a4c2be53394138212fed56f0dfc4\00")
)

;; lifted analysis
;; func func0 (; func0 ;)
;;   param v0: i32
;;   param v1: i64
;;   semantic TryFromVal: int::obj_to_u64
;;   semantic ArithmeticOp: and
;;   semantic ArithmeticOp: shr
;;   semantic ComparisonOp: eq
;;   calls
;;   i::0 -> i::0
;;   block block0
;;     param v0: i32
;;     param v1: i64
;;     v2 = I32WrapI64 v1
;;     v3 = I32Const ["255"]
;;     v4 = I32And v2, v3
;;       semantic ArithmeticOp: and
;;     v5 = I32Const ["64"]
;;     v6 = I32Eq v4, v5
;;       semantic ComparisonOp: eq
;;     successors: block3, block4
;;     terminator: if v6 then block3(v0, v1) else block4(v4, v0, v1)
;;   block block1
;;     terminator: return
;;   block block2
;;     param v20: i32
;;     param v25: i64
;;     param v27: i64
;;     I64Store v20, v25 ["memory0", "align=3", "offset=0"]
;;     I64Store v20, v27 ["memory0", "align=3", "offset=8"]
;;     successors: block1
;;     terminator: br block1
;;   block block3
;;     param v29: i32
;;     param v30: i64
;;     v17 = I64Const ["0"]
;;     v19 = Call v30 ["i::0"]
;;       semantic TryFromVal: int::obj_to_u64
;;     successors: block2
;;     terminator: br block2(v29, v17, v19)
;;   block block4
;;     param v31: i32
;;     param v33: i32
;;     param v35: i64
;;     v8 = I32Const ["6"]
;;     v9 = I32Eq v31, v8
;;       semantic ComparisonOp: eq
;;     successors: block5, block6
;;     terminator: if v9 then block5(v33, v35) else block6(v33)
;;   block block5
;;     param v32: i32
;;     param v34: i64
;;     v14 = I64Const ["8"]
;;     v15 = I64ShrU v34, v14
;;       semantic ArithmeticOp: shr
;;     v16 = I64Const ["0"]
;;     successors: block2
;;     terminator: br block2(v32, v16, v15)
;;   block block6
;;     param v36: i32
;;     v10 = I64Const ["1"]
;;     v11 = I64Const ["34359740419"]
;;     successors: block2
;;     terminator: br block2(v36, v10, v11)

;; func add (; func1 ;)
;;   export: add
;;   param a: u64
;;   param b: u64
;;   result u64
;;   semantic EntryPoint: Contract entry point `add`
;;   semantic IntoVal: int::obj_from_u64
;;   semantic TryFromVal: int::obj_to_u64
;;   semantic ArithmeticOp: add
;;   semantic ArithmeticOp: and
;;   semantic ArithmeticOp: or
;;   semantic ArithmeticOp: shl
;;   semantic ArithmeticOp: shr
;;   semantic ArithmeticOp: sub
;;   semantic ComparisonOp: eq
;;   semantic ComparisonOp: gt
;;   semantic ComparisonOp: lt
;;   calls
;;   func0 -> func0
;;   func2 -> func2
;;   i::_ -> i::_
;;   block block0
;;     param v1: i64
;;     param v2: i64
;;     v3 = GlobalGet ["global0"]
;;     v4 = I32Const ["16"]
;;     v5 = I32Sub v3, v4
;;       semantic ArithmeticOp: sub
;;     GlobalSet v5 ["global0"]
;;     Call v5, v1 ["func0"]
;;     v8 = I32Load v5 ["memory0", "align=2", "offset=0"]
;;     v9 = I32Const ["1"]
;;     v10 = I32Eq v8, v9
;;       semantic ComparisonOp: eq
;;     successors: block3, block4
;;     terminator: if v10 then block3 else block4(v2, v5)
;;   block block1
;;     param v0: i64
;;     terminator: none
;;   block block2
;;     Call ["func2"]
;;     terminator: unreachable
;;   block block3
;;     terminator: unreachable
;;   block block4
;;     param v42: i64
;;     param v43: i32
;;     v12 = I64Load v43 ["memory0", "align=3", "offset=8"]
;;     Call v43, v42 ["func0"]
;;     v15 = I32Load v43 ["memory0", "align=2", "offset=0"]
;;     v16 = I32Const ["1"]
;;     v17 = I32Eq v15, v16
;;       semantic ComparisonOp: eq
;;     successors: block3, block5
;;     terminator: if v17 then block3 else block5(v43, v12)
;;   block block5
;;     param v44: i32
;;     param v45: i64
;;     v19 = I64Load v44 ["memory0", "align=3", "offset=8"]
;;     v21 = I64Add v19, v45
;;       semantic ArithmeticOp: add
;;     v22 = I64LtU v21, v19
;;       semantic ComparisonOp: lt
;;     successors: block2, block6
;;     terminator: if v22 then block2 else block6(v21, v44)
;;   block block6
;;     param v46: i64
;;     param v48: i32
;;     v24 = I64Const ["72057594037927935"]
;;     v25 = I64GtU v46, v24
;;       semantic ComparisonOp: gt
;;     successors: block8, block9
;;     terminator: if v25 then block8(v48, v46) else block9(v48, v46)
;;   block block7
;;     param v33: i32
;;     param v40: i64
;;     v37 = I32Const ["16"]
;;     v38 = I32Add v33, v37
;;       semantic ArithmeticOp: add
;;     GlobalSet v38 ["global0"]
;;     terminator: return v40
;;   block block8
;;     param v47: i32
;;     param v49: i64
;;     v32 = Call v49 ["i::_"]
;;       semantic IntoVal: int::obj_from_u64
;;     successors: block7
;;     terminator: br block7(v47, v32)
;;   block block9
;;     param v50: i32
;;     param v51: i64
;;     v27 = I64Const ["8"]
;;     v28 = I64Shl v51, v27
;;       semantic ArithmeticOp: shl
;;     v29 = I64Const ["6"]
;;     v30 = I64Or v28, v29
;;       semantic ArithmeticOp: or
;;     successors: block7
;;     terminator: br block7(v50, v30)

;; func func2 (; func2 ;)
;;   calls
;;   func3 -> func3
;;   block block0
;;     Call ["func3"]
;;     terminator: unreachable
;;   block block1
;;     terminator: none

;; func func3 (; func3 ;)
;;   block block0
;;     terminator: unreachable
;;   block block1
;;     terminator: none

;; func _ (; func4 ;)
;;   export: _
;;   semantic Dispatcher: Contract dispatch entry point
;;   block block0
;;     successors: block1
;;     terminator: br block1
;;   block block1
;;     terminator: return

