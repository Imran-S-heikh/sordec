;; Soroban Annotated WAT
;; sections
;; type [10..59]
;; import [61..104]
;; function [106..120]
;; memory [122..125]
;; global [127..152]
;; export [154..247]
;; code [250..1310]
;; data [1312..1333]
;; custom:contractspecv0 [1336..1623]
;; custom:contractenvmetav0 [1625..1655]
;; custom:contractmetav0 [1657..1768]
;; imports
;; #0 l::1 func(type=0)
;; #1 l::_ func(type=1)
;; #2 a::0 func(type=2)
;; #3 x::1 func(type=0)
;; #4 v::g func(type=0)
;; #5 b::j func(type=0)
;; #6 l::0 func(type=0)
;; exports
;; memory -> Memory#0
;; __constructor -> Func#12
;; get_admin -> Func#13
;; get_count -> Func#15
;; increment -> Func#16
;; _ -> Func#19
;; __data_end -> Global#1
;; __heap_base -> Global#2
;; interface
;; fn get_admin() -> Address
;; fn get_count(user: Address) -> u32
;; fn increment(user: Address) -> u32
;; fn __constructor(admin: Address) -> ()
;; contract metadata
;; rssdkver = 21.7.7#5da789c50b18a4c2be53394138212fed56f0dfc4
;; rsver = 1.91.1
;; environment: protocol=Some("21"), pre_release=Some("0")

(module
  (type (;0;) (func (param i64 i64) (result i64)))
  (type (;1;) (func (param i64 i64 i64) (result i64)))
  (type (;2;) (func (param i64) (result i64)))
  (type (;3;) (func (param i32 i64)))
  (type (;4;) (func (param i64 i64) (result i32)))
  (type (;5;) (func (param i32 i32 i32)))
  (type (;6;) (func (param i32 i32) (result i64)))
  (type (;7;) (func (result i64)))
  (type (;8;) (func))
  (import "l" "1" (func (;0;) (type 0)))
  (import "l" "_" (func (;1;) (type 1)))
  (import "a" "0" (func (;2;) (type 2)))
  (import "x" "1" (func (;3;) (type 0)))
  (import "v" "g" (func (;4;) (type 0)))
  (import "b" "j" (func (;5;) (type 0)))
  (import "l" "0" (func (;6;) (type 0)))
  (memory (;0;) 17)
  (global (;0;) (mut i32) i32.const 1048576)
  (global (;1;) i32 i32.const 1048588)
  (global (;2;) i32 i32.const 1048592)
  (export "memory" (memory 0))
  (export "__constructor" (func 12))
  (export "get_admin" (func 13))
  (export "get_count" (func 15))
  (export "increment" (func 16))
  (export "_" (func 19))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2))
  (func (;7;) (type 3) (param i32 i64)
    (local i32 i32)
    block ;; label = @1
      block ;; label = @2
        block ;; label = @3
          i64.const 0
          local.get 1
          call 8
          local.tee 1
          i64.const 1
          call 9
          br_if 0 (;@3;)
          i32.const 0
          local.set 2
          br 1 (;@2;)
        end
        local.get 1
        i64.const 1
        call 0
        local.tee 1
        i64.const 255
        i64.and
        i64.const 4
        i64.ne
        br_if 1 (;@1;)
        local.get 1
        i64.const 32
        i64.shr_u
        i32.wrap_i64
        local.set 3
        i32.const 1
        local.set 2
      end
      local.get 0
      local.get 3
      i32.store offset=4
      local.get 0
      local.get 2
      i32.store
      return
    end
    unreachable
  )
  (func (;8;) (type 0) (param i64 i64) (result i64)
    (local i32)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 2
    global.set 0
    block ;; label = @1
      block ;; label = @2
        block ;; label = @3
          local.get 0
          i32.wrap_i64
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.const 1048583
          i32.const 5
          call 10
          local.get 2
          i32.load
          br_if 2 (;@1;)
          local.get 2
          local.get 2
          i64.load offset=8
          i64.store
          local.get 2
          i32.const 1
          call 11
          local.set 0
          br 1 (;@2;)
        end
        local.get 2
        i32.const 1048576
        i32.const 7
        call 10
        local.get 2
        i32.load
        br_if 1 (;@1;)
        local.get 2
        i64.load offset=8
        local.set 0
        local.get 2
        local.get 1
        i64.store offset=8
        local.get 2
        local.get 0
        i64.store
        local.get 2
        i32.const 2
        call 11
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
  )
  (func (;9;) (type 4) (param i64 i64) (result i32)
    local.get 0
    local.get 1
    call 6
    i64.const 1
    i64.eq
  )
  (func (;10;) (type 5) (param i32 i32 i32)
    (local i32 i64 i32 i32 i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 3
    global.set 0
    i64.const 0
    local.set 4
    local.get 2
    local.set 5
    local.get 1
    local.set 6
    loop ;; label = @1
      block ;; label = @2
        block ;; label = @3
          block ;; label = @4
            block ;; label = @5
              block ;; label = @6
                local.get 5
                i32.eqz
                br_if 0 (;@6;)
                i32.const 1
                local.set 7
                local.get 6
                i32.load8_u
                local.tee 8
                i32.const 95
                i32.eq
                br_if 4 (;@2;)
                local.get 8
                i32.const -48
                i32.add
                i32.const 255
                i32.and
                i32.const 10
                i32.lt_u
                br_if 2 (;@4;)
                local.get 8
                i32.const -65
                i32.add
                i32.const 255
                i32.and
                i32.const 26
                i32.lt_u
                br_if 3 (;@3;)
                block ;; label = @7
                  local.get 8
                  i32.const -97
                  i32.add
                  i32.const 255
                  i32.and
                  i32.const 26
                  i32.ge_u
                  br_if 0 (;@7;)
                  local.get 8
                  i32.const -59
                  i32.add
                  local.set 7
                  br 5 (;@2;)
                end
                local.get 3
                local.get 8
                i64.extend_i32_u
                i64.const 8
                i64.shl
                i64.const 1
                i64.or
                i64.store
                local.get 1
                i64.extend_i32_u
                i64.const 32
                i64.shl
                i64.const 4
                i64.or
                local.get 2
                i64.extend_i32_u
                i64.const 32
                i64.shl
                i64.const 4
                i64.or
                call 5
                local.set 4
                br 1 (;@5;)
              end
              local.get 3
              local.get 4
              i64.const 8
              i64.shl
              i64.const 14
              i64.or
              local.tee 4
              i64.store offset=4 align=4
            end
            local.get 0
            i64.const 0
            i64.store
            local.get 0
            local.get 4
            i64.store offset=8
            local.get 3
            i32.const 16
            i32.add
            global.set 0
            return
          end
          local.get 8
          i32.const -46
          i32.add
          local.set 7
          br 1 (;@2;)
        end
        local.get 8
        i32.const -53
        i32.add
        local.set 7
      end
      local.get 4
      i64.const 6
      i64.shl
      local.get 7
      i64.extend_i32_u
      i64.const 255
      i64.and
      i64.or
      local.set 4
      local.get 5
      i32.const -1
      i32.add
      local.set 5
      local.get 6
      i32.const 1
      i32.add
      local.set 6
      br 0 (;@1;)
    end
  )
  (func (;11;) (type 6) (param i32 i32) (result i64)
    local.get 0
    i64.extend_i32_u
    i64.const 32
    i64.shl
    i64.const 4
    i64.or
    local.get 1
    i64.extend_i32_u
    i64.const 32
    i64.shl
    i64.const 4
    i64.or
    call 4
  )
  (func (;12;) (type 2) (param i64) (result i64)
    block ;; label = @1
      local.get 0
      i64.const 255
      i64.and
      i64.const 77
      i64.eq
      br_if 0 (;@1;)
      unreachable
    end
    i64.const 1
    local.get 0
    call 8
    local.get 0
    i64.const 2
    call 1
    drop
    i64.const 2
  )
  (func (;13;) (type 7) (result i64)
    (local i64)
    block ;; label = @1
      block ;; label = @2
        i64.const 1
        local.get 0
        call 8
        local.tee 0
        i64.const 2
        call 9
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i64.const 2
        call 0
        local.tee 0
        i64.const 255
        i64.and
        i64.const 77
        i64.eq
        br_if 1 (;@1;)
        unreachable
      end
      call 14
      unreachable
    end
    local.get 0
  )
  (func (;14;) (type 8)
    call 17
    unreachable
  )
  (func (;15;) (type 2) (param i64) (result i64)
    (local i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 1
    global.set 0
    block ;; label = @1
      local.get 0
      i64.const 255
      i64.and
      i64.const 77
      i64.eq
      br_if 0 (;@1;)
      unreachable
    end
    local.get 1
    i32.const 8
    i32.add
    local.get 0
    call 7
    local.get 1
    i32.load offset=8
    local.set 2
    local.get 1
    i64.load32_u offset=12
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set 0
    local.get 0
    i64.const 32
    i64.shl
    i64.const 4
    i64.or
    i64.const 4
    local.get 2
    i32.const 1
    i32.and
    select
  )
  (func (;16;) (type 2) (param i64) (result i64)
    (local i32 i32 i32 i64)
    global.get 0
    i32.const 48
    i32.sub
    local.tee 1
    global.set 0
    block ;; label = @1
      block ;; label = @2
        local.get 0
        i64.const 255
        i64.and
        i64.const 77
        i64.ne
        br_if 0 (;@2;)
        local.get 0
        call 2
        drop
        local.get 1
        i32.const 8
        i32.add
        local.get 0
        call 7
        i32.const 0
        local.set 2
        local.get 1
        i32.load offset=12
        i32.const 0
        local.get 1
        i32.load offset=8
        i32.const 1
        i32.and
        select
        local.tee 3
        i32.const -1
        i32.eq
        br_if 1 (;@1;)
        i64.const 0
        local.get 0
        call 8
        local.get 3
        i32.const 1
        i32.add
        i64.extend_i32_u
        i64.const 32
        i64.shl
        i64.const 4
        i64.or
        local.tee 4
        i64.const 1
        call 1
        drop
        local.get 1
        local.get 0
        i64.store offset=24
        local.get 1
        i64.const 3372789210509277454
        i64.store offset=16
        loop ;; label = @3
          block ;; label = @4
            local.get 2
            i32.const 16
            i32.ne
            br_if 0 (;@4;)
            i32.const 0
            local.set 2
            block ;; label = @5
              loop ;; label = @6
                local.get 2
                i32.const 16
                i32.eq
                br_if 1 (;@5;)
                local.get 1
                i32.const 32
                i32.add
                local.get 2
                i32.add
                local.get 1
                i32.const 16
                i32.add
                local.get 2
                i32.add
                i64.load
                i64.store
                local.get 2
                i32.const 8
                i32.add
                local.set 2
                br 0 (;@6;)
              end
            end
            local.get 1
            i32.const 32
            i32.add
            i32.const 2
            call 11
            local.get 4
            call 3
            drop
            local.get 1
            i32.const 48
            i32.add
            global.set 0
            local.get 4
            return
          end
          local.get 1
          i32.const 32
          i32.add
          local.get 2
          i32.add
          i64.const 2
          i64.store
          local.get 2
          i32.const 8
          i32.add
          local.set 2
          br 0 (;@3;)
        end
      end
      unreachable
    end
    call 17
    unreachable
  )
  (func (;17;) (type 8)
    call 18
    unreachable
  )
  (func (;18;) (type 8)
    unreachable
  )
  (func (;19;) (type 8))
  (data (;0;) (i32.const 1048576) "CounterAdmin")
  (@custom "contractspecv0" (after data) "\00\00\00\00\00\00\00\00\00\00\00\09get_admin\00\00\00\00\00\00\00\00\00\00\01\00\00\00\13\00\00\00\00\00\00\00\00\00\00\00\09get_count\00\00\00\00\00\00\01\00\00\00\00\00\00\00\04user\00\00\00\13\00\00\00\01\00\00\00\04\00\00\00\00\00\00\00\00\00\00\00\09increment\00\00\00\00\00\00\01\00\00\00\00\00\00\00\04user\00\00\00\13\00\00\00\01\00\00\00\04\00\00\00\02\00\00\00\00\00\00\00\00\00\00\00\07DataKey\00\00\00\00\02\00\00\00\01\00\00\00\00\00\00\00\07Counter\00\00\00\00\01\00\00\00\13\00\00\00\00\00\00\00\00\00\00\00\05Admin\00\00\00\00\00\00\00\00\00\00\00\00\00\00\0d__constructor\00\00\00\00\00\00\01\00\00\00\00\00\00\00\05admin\00\00\00\00\00\00\13\00\00\00\00")
  (@custom "contractenvmetav0" (after data) "\00\00\00\00\00\00\00\15\00\00\00\00")
  (@custom "contractmetav0" (after data) "\00\00\00\00\00\00\00\05rsver\00\00\00\00\00\00\061.91.1\00\00\00\00\00\00\00\00\00\08rssdkver\00\00\00/21.7.7#5da789c50b18a4c2be53394138212fed56f0dfc4\00")
)

;; lifted analysis
;; func func0 (; func0 ;)
;;   param v0: i32
;;   param v1: i64
;;   semantic StorageGet: ledger::get_contract_data
;;   semantic StorageHas: ledger::has_contract_data
;;   semantic VectorOp: vec::vec_new_from_linear_memory
;;   semantic StringOrSymbolOp: buf::symbol_new_from_linear_memory
;;   semantic ArithmeticOp: add
;;   semantic ArithmeticOp: and
;;   semantic ArithmeticOp: or
;;   semantic ArithmeticOp: shl
;;   semantic ArithmeticOp: shr
;;   semantic ArithmeticOp: sub
;;   semantic ComparisonOp: eq
;;   semantic ComparisonOp: eqz
;;   semantic ComparisonOp: ge
;;   semantic ComparisonOp: lt
;;   semantic ComparisonOp: ne
;;   calls
;;   func1 -> func1
;;   func2 -> func2
;;   l::1 -> l::1
;;   block block0
;;     param v0: i32
;;     param v1: i64
;;     v2 = I64Const ["0"]
;;     v3 = Call v2, v1 ["func1"]
;;     v4 = I64Const ["1"]
;;     v5 = Call v3, v4 ["func2"]
;;     v25 = I32Const ["0"]
;;     successors: block4, block5
;;     terminator: if v5 then block4(v3, v0) else block5(v0, v25)
;;   block block1
;;     terminator: none
;;   block block2
;;     terminator: unreachable
;;   block block3
;;     param v19: i32
;;     param v23: i32
;;     param v27: i32
;;     I32Store v19, v23 ["memory0", "align=2", "offset=4"]
;;     I32Store v19, v27 ["memory0", "align=2", "offset=0"]
;;     terminator: return
;;   block block4
;;     param v29: i64
;;     param v33: i32
;;     v8 = I64Const ["1"]
;;     v9 = Call v29, v8 ["l::1"]
;;       semantic StorageGet: ledger::get_contract_data
;;     v10 = I64Const ["255"]
;;     v11 = I64And v9, v10
;;       semantic ArithmeticOp: and
;;     v12 = I64Const ["4"]
;;     v13 = I64Ne v11, v12
;;       semantic ComparisonOp: ne
;;     successors: block2, block6
;;     terminator: if v13 then block2 else block6(v33, v9)
;;   block block5
;;     param v30: i32
;;     param v31: i32
;;     v6 = I32Const ["0"]
;;     successors: block3
;;     terminator: br block3(v30, v31, v6)
;;   block block6
;;     param v32: i32
;;     param v34: i64
;;     v15 = I64Const ["32"]
;;     v16 = I64ShrU v34, v15
;;       semantic ArithmeticOp: shr
;;     v17 = I32WrapI64 v16
;;     v18 = I32Const ["1"]
;;     successors: block3
;;     terminator: br block3(v32, v17, v18)

;; func func1 (; func1 ;)
;;   param v0: i64
;;   param v1: i64
;;   result i64
;;   semantic VectorOp: vec::vec_new_from_linear_memory
;;   semantic StringOrSymbolOp: buf::symbol_new_from_linear_memory
;;   semantic ArithmeticOp: add
;;   semantic ArithmeticOp: and
;;   semantic ArithmeticOp: or
;;   semantic ArithmeticOp: shl
;;   semantic ArithmeticOp: sub
;;   semantic ComparisonOp: eq
;;   semantic ComparisonOp: eqz
;;   semantic ComparisonOp: ge
;;   semantic ComparisonOp: lt
;;   calls
;;   func3 -> func3
;;   func4 -> func4
;;   block block0
;;     param v1: i64
;;     param v2: i64
;;     v3 = GlobalGet ["global0"]
;;     v4 = I32Const ["16"]
;;     v5 = I32Sub v3, v4
;;       semantic ArithmeticOp: sub
;;     GlobalSet v5 ["global0"]
;;     v7 = I32WrapI64 v1
;;     v8 = I32Const ["1"]
;;     v9 = I32And v7, v8
;;       semantic ArithmeticOp: and
;;     v10 = I32Eqz v9
;;       semantic ComparisonOp: eqz
;;     successors: block4, block5
;;     terminator: if v10 then block4(v5, v2) else block5(v5)
;;   block block1
;;     param v0: i64
;;     terminator: none
;;   block block2
;;     terminator: unreachable
;;   block block3
;;     param v34: i32
;;     param v38: i64
;;     v35 = I32Const ["16"]
;;     v36 = I32Add v34, v35
;;       semantic ArithmeticOp: add
;;     GlobalSet v36 ["global0"]
;;     terminator: return v38
;;   block block4
;;     param v39: i32
;;     param v43: i64
;;     v22 = I32Const ["1048576"]
;;     v23 = I32Const ["7"]
;;     Call v39, v22, v23 ["func3"]
;;     v25 = I32Load v39 ["memory0", "align=2", "offset=0"]
;;     successors: block2, block7
;;     terminator: if v25 then block2 else block7(v43, v39)
;;   block block5
;;     param v40: i32
;;     v12 = I32Const ["1048583"]
;;     v13 = I32Const ["5"]
;;     Call v40, v12, v13 ["func3"]
;;     v15 = I32Load v40 ["memory0", "align=2", "offset=0"]
;;     successors: block2, block6
;;     terminator: if v15 then block2 else block6(v40)
;;   block block6
;;     param v41: i32
;;     v17 = I64Load v41 ["memory0", "align=3", "offset=8"]
;;     I64Store v41, v17 ["memory0", "align=3", "offset=0"]
;;     v19 = I32Const ["1"]
;;     v20 = Call v41, v19 ["func4"]
;;     successors: block3
;;     terminator: br block3(v41, v20)
;;   block block7
;;     param v42: i64
;;     param v44: i32
;;     v27 = I64Load v44 ["memory0", "align=3", "offset=8"]
;;     I64Store v44, v42 ["memory0", "align=3", "offset=8"]
;;     I64Store v44, v27 ["memory0", "align=3", "offset=0"]
;;     v32 = I32Const ["2"]
;;     v33 = Call v44, v32 ["func4"]
;;     successors: block3
;;     terminator: br block3(v44, v33)

;; func func2 (; func2 ;)
;;   param v0: i64
;;   param v1: i64
;;   result i32
;;   semantic StorageHas: ledger::has_contract_data
;;   semantic ComparisonOp: eq
;;   calls
;;   l::0 -> l::0
;;   block block0
;;     param v1: i64
;;     param v2: i64
;;     v3 = Call v1, v2 ["l::0"]
;;       semantic StorageHas: ledger::has_contract_data
;;     v4 = I64Const ["1"]
;;     v5 = I64Eq v3, v4
;;       semantic ComparisonOp: eq
;;     successors: block1
;;     terminator: br block1(v5)
;;   block block1
;;     param v0: i32
;;     terminator: return v0

;; func func3 (; func3 ;)
;;   param v0: i32
;;   param v1: i32
;;   param v2: i32
;;   semantic StringOrSymbolOp: buf::symbol_new_from_linear_memory
;;   semantic ArithmeticOp: add
;;   semantic ArithmeticOp: and
;;   semantic ArithmeticOp: or
;;   semantic ArithmeticOp: shl
;;   semantic ArithmeticOp: sub
;;   semantic ComparisonOp: eq
;;   semantic ComparisonOp: eqz
;;   semantic ComparisonOp: ge
;;   semantic ComparisonOp: lt
;;   calls
;;   b::j -> b::j
;;   block block0
;;     param v0: i32
;;     param v1: i32
;;     param v2: i32
;;     v3 = GlobalGet ["global0"]
;;     v4 = I32Const ["16"]
;;     v5 = I32Sub v3, v4
;;       semantic ArithmeticOp: sub
;;     GlobalSet v5 ["global0"]
;;     v7 = I64Const ["0"]
;;     successors: block2
;;     terminator: br block2(v2, v1, v5, v1, v2, v7, v0)
;;   block block1
;;     terminator: none
;;   block block2
;;     param v8: i32
;;     param v12: i32
;;     param v45: i32
;;     param v58: i32
;;     param v69: i32
;;     param v78: i64
;;     param v90: i32
;;     v9 = I32Eqz v8
;;       semantic ComparisonOp: eqz
;;     successors: block8, block9
;;     terminator: if v9 then block8(v45, v78, v90) else block9(v8, v12, v45, v58, v69, v78, v90)
;;   block block3
;;     terminator: none
;;   block block4
;;     param v106: i64
;;     param v116: i32
;;     param v121: i32
;;     param v131: i32
;;     param v140: i32
;;     param v144: i32
;;     param v148: i32
;;     param v152: i32
;;     v114 = I64Const ["6"]
;;     v115 = I64Shl v106, v114
;;       semantic ArithmeticOp: shl
;;     v117 = I64ExtendI32U v116
;;     v118 = I64Const ["255"]
;;     v119 = I64And v117, v118
;;       semantic ArithmeticOp: and
;;     v120 = I64Or v115, v119
;;       semantic ArithmeticOp: or
;;     v129 = I32Const ["-1"]
;;     v130 = I32Add v121, v129
;;       semantic ArithmeticOp: add
;;     v138 = I32Const ["1"]
;;     v139 = I32Add v131, v138
;;       semantic ArithmeticOp: add
;;     successors: block2
;;     terminator: br block2(v130, v139, v140, v144, v148, v120, v152)
;;   block block5
;;     param v156: i32
;;     param v160: i32
;;     param v164: i32
;;     param v167: i32
;;     param v171: i32
;;     param v175: i32
;;     param v179: i64
;;     param v183: i32
;;     v104 = I32Const ["-53"]
;;     v105 = I32Add v164, v104
;;       semantic ArithmeticOp: add
;;     successors: block4
;;     terminator: br block4(v179, v105, v156, v160, v167, v171, v175, v183)
;;   block block6
;;     param v187: i32
;;     param v188: i32
;;     param v189: i32
;;     param v190: i32
;;     param v191: i32
;;     param v192: i32
;;     param v193: i64
;;     param v194: i32
;;     v101 = I32Const ["-46"]
;;     v102 = I32Add v189, v101
;;       semantic ArithmeticOp: add
;;     successors: block4
;;     terminator: br block4(v193, v102, v187, v188, v190, v191, v192, v194)
;;   block block7
;;     param v84: i32
;;     param v94: i64
;;     param v96: i32
;;     v92 = I64Const ["0"]
;;     I64Store v84, v92 ["memory0", "align=3", "offset=0"]
;;     I64Store v84, v94 ["memory0", "align=3", "offset=8"]
;;     v97 = I32Const ["16"]
;;     v98 = I32Add v96, v97
;;       semantic ArithmeticOp: add
;;     GlobalSet v98 ["global0"]
;;     terminator: return
;;   block block8
;;     param v195: i32
;;     param v196: i64
;;     param v197: i32
;;     v79 = I64Const ["8"]
;;     v80 = I64Shl v196, v79
;;       semantic ArithmeticOp: shl
;;     v81 = I64Const ["14"]
;;     v82 = I64Or v80, v81
;;       semantic ArithmeticOp: or
;;     I64Store v195, v82 ["memory0", "align=2", "offset=4"]
;;     successors: block7
;;     terminator: br block7(v197, v82, v195)
;;   block block9
;;     param v159: i32
;;     param v163: i32
;;     param v170: i32
;;     param v174: i32
;;     param v178: i32
;;     param v182: i64
;;     param v186: i32
;;     v10 = I32Const ["1"]
;;     v13 = I32Load8U v163 ["memory0", "align=0", "offset=0"]
;;     v14 = I32Const ["95"]
;;     v15 = I32Eq v13, v14
;;       semantic ComparisonOp: eq
;;     successors: block4, block10
;;     terminator: if v15 then block4(v182, v10, v159, v163, v170, v174, v178, v186) else block10(v159, v163, v13, v170, v174, v178, v182, v186)
;;   block block10
;;     param v158: i32
;;     param v162: i32
;;     param v166: i32
;;     param v169: i32
;;     param v173: i32
;;     param v177: i32
;;     param v181: i64
;;     param v185: i32
;;     v17 = I32Const ["-48"]
;;     v18 = I32Add v166, v17
;;       semantic ArithmeticOp: add
;;     v19 = I32Const ["255"]
;;     v20 = I32And v18, v19
;;       semantic ArithmeticOp: and
;;     v21 = I32Const ["10"]
;;     v22 = I32LtU v20, v21
;;       semantic ComparisonOp: lt
;;     successors: block6, block11
;;     terminator: if v22 then block6(v158, v162, v166, v169, v173, v177, v181, v185) else block11(v158, v162, v166, v169, v173, v177, v181, v185)
;;   block block11
;;     param v157: i32
;;     param v161: i32
;;     param v165: i32
;;     param v168: i32
;;     param v172: i32
;;     param v176: i32
;;     param v180: i64
;;     param v184: i32
;;     v24 = I32Const ["-65"]
;;     v25 = I32Add v165, v24
;;       semantic ArithmeticOp: add
;;     v26 = I32Const ["255"]
;;     v27 = I32And v25, v26
;;       semantic ArithmeticOp: and
;;     v28 = I32Const ["26"]
;;     v29 = I32LtU v27, v28
;;       semantic ComparisonOp: lt
;;     successors: block5, block12
;;     terminator: if v29 then block5(v157, v161, v165, v168, v172, v176, v180, v184) else block12(v165, v168, v172, v176, v184, v157, v161, v180)
;;   block block12
;;     param v198: i32
;;     param v201: i32
;;     param v203: i32
;;     param v205: i32
;;     param v207: i32
;;     param v209: i32
;;     param v211: i32
;;     param v217: i64
;;     v31 = I32Const ["-97"]
;;     v32 = I32Add v198, v31
;;       semantic ArithmeticOp: add
;;     v33 = I32Const ["255"]
;;     v34 = I32And v32, v33
;;       semantic ArithmeticOp: and
;;     v35 = I32Const ["26"]
;;     v36 = I32GeU v34, v35
;;       semantic ComparisonOp: ge
;;     successors: block13, block14
;;     terminator: if v36 then block13(v198, v201, v203, v205, v207) else block14(v209, v211, v198, v201, v203, v205, v217, v207)
;;   block block13
;;     param v199: i32
;;     param v200: i32
;;     param v202: i32
;;     param v204: i32
;;     param v206: i32
;;     v47 = I64ExtendI32U v199
;;     v48 = I64Const ["8"]
;;     v49 = I64Shl v47, v48
;;       semantic ArithmeticOp: shl
;;     v50 = I64Const ["1"]
;;     v51 = I64Or v49, v50
;;       semantic ArithmeticOp: or
;;     I64Store v200, v51 ["memory0", "align=3", "offset=0"]
;;     v59 = I64ExtendI32U v202
;;     v60 = I64Const ["32"]
;;     v61 = I64Shl v59, v60
;;       semantic ArithmeticOp: shl
;;     v62 = I64Const ["4"]
;;     v63 = I64Or v61, v62
;;       semantic ArithmeticOp: or
;;     v70 = I64ExtendI32U v204
;;     v71 = I64Const ["32"]
;;     v72 = I64Shl v70, v71
;;       semantic ArithmeticOp: shl
;;     v73 = I64Const ["4"]
;;     v74 = I64Or v72, v73
;;       semantic ArithmeticOp: or
;;     v75 = Call v63, v74 ["b::j"]
;;       semantic StringOrSymbolOp: buf::symbol_new_from_linear_memory
;;     successors: block7
;;     terminator: br block7(v206, v75, v200)
;;   block block14
;;     param v208: i32
;;     param v210: i32
;;     param v212: i32
;;     param v213: i32
;;     param v214: i32
;;     param v215: i32
;;     param v216: i64
;;     param v218: i32
;;     v38 = I32Const ["-59"]
;;     v39 = I32Add v212, v38
;;       semantic ArithmeticOp: add
;;     successors: block4
;;     terminator: br block4(v216, v39, v208, v210, v213, v214, v215, v218)

;; func func4 (; func4 ;)
;;   param v0: i32
;;   param v1: i32
;;   result i64
;;   semantic VectorOp: vec::vec_new_from_linear_memory
;;   semantic ArithmeticOp: or
;;   semantic ArithmeticOp: shl
;;   calls
;;   v::g -> v::g
;;   block block0
;;     param v1: i32
;;     param v2: i32
;;     v3 = I64ExtendI32U v1
;;     v4 = I64Const ["32"]
;;     v5 = I64Shl v3, v4
;;       semantic ArithmeticOp: shl
;;     v6 = I64Const ["4"]
;;     v7 = I64Or v5, v6
;;       semantic ArithmeticOp: or
;;     v8 = I64ExtendI32U v2
;;     v9 = I64Const ["32"]
;;     v10 = I64Shl v8, v9
;;       semantic ArithmeticOp: shl
;;     v11 = I64Const ["4"]
;;     v12 = I64Or v10, v11
;;       semantic ArithmeticOp: or
;;     v13 = Call v7, v12 ["v::g"]
;;       semantic VectorOp: vec::vec_new_from_linear_memory
;;     successors: block1
;;     terminator: br block1(v13)
;;   block block1
;;     param v0: i64
;;     terminator: return v0

;; func __constructor (; func5 ;)
;;   export: __constructor
;;   param admin: Address
;;   semantic Constructor: Contract constructor entry point
;;   semantic StorageSet: ledger::put_contract_data
;;   semantic VectorOp: vec::vec_new_from_linear_memory
;;   semantic StringOrSymbolOp: buf::symbol_new_from_linear_memory
;;   semantic ArithmeticOp: add
;;   semantic ArithmeticOp: and
;;   semantic ArithmeticOp: or
;;   semantic ArithmeticOp: shl
;;   semantic ArithmeticOp: sub
;;   semantic ComparisonOp: eq
;;   semantic ComparisonOp: eqz
;;   semantic ComparisonOp: ge
;;   semantic ComparisonOp: lt
;;   calls
;;   func1 -> func1
;;   l::_ -> l::_
;;   block block0
;;     param v1: i64
;;     v2 = I64Const ["255"]
;;     v3 = I64And v1, v2
;;       semantic ArithmeticOp: and
;;     v4 = I64Const ["77"]
;;     v5 = I64Eq v3, v4
;;       semantic ComparisonOp: eq
;;     successors: block2, block3
;;     terminator: if v5 then block2(v1) else block3
;;   block block1
;;     param v0: i64
;;     terminator: return v0
;;   block block2
;;     param v12: i64
;;     v6 = I64Const ["1"]
;;     v8 = Call v6, v12 ["func1"]
;;     v9 = I64Const ["2"]
;;     v10 = Call v8, v12, v9 ["l::_"]
;;       semantic StorageSet: ledger::put_contract_data
;;     v11 = I64Const ["2"]
;;     successors: block1
;;     terminator: br block1(v11)
;;   block block3
;;     terminator: unreachable

;; func get_admin (; func6 ;)
;;   export: get_admin
;;   result Address
;;   semantic EntryPoint: Contract entry point `get_admin`
;;   semantic StorageGet: ledger::get_contract_data
;;   semantic StorageHas: ledger::has_contract_data
;;   semantic VectorOp: vec::vec_new_from_linear_memory
;;   semantic StringOrSymbolOp: buf::symbol_new_from_linear_memory
;;   semantic ArithmeticOp: add
;;   semantic ArithmeticOp: and
;;   semantic ArithmeticOp: or
;;   semantic ArithmeticOp: shl
;;   semantic ArithmeticOp: sub
;;   semantic ComparisonOp: eq
;;   semantic ComparisonOp: eqz
;;   semantic ComparisonOp: ge
;;   semantic ComparisonOp: lt
;;   calls
;;   func1 -> func1
;;   func2 -> func2
;;   func7 -> func7
;;   l::1 -> l::1
;;   block block0
;;     v1 = I64Const ["1"]
;;     v2 = I64Const ["0"]
;;     v3 = Call v1, v2 ["func1"]
;;     v4 = I64Const ["2"]
;;     v5 = Call v3, v4 ["func2"]
;;     v6 = I32Eqz v5
;;       semantic ComparisonOp: eqz
;;     successors: block3, block4
;;     terminator: if v6 then block3 else block4(v3)
;;   block block1
;;     param v0: i64
;;     terminator: return v0
;;   block block2
;;     param v16: i64
;;     successors: block1
;;     terminator: br block1(v16)
;;   block block3
;;     Call ["func7"]
;;     terminator: unreachable
;;   block block4
;;     param v17: i64
;;     v8 = I64Const ["2"]
;;     v9 = Call v17, v8 ["l::1"]
;;       semantic StorageGet: ledger::get_contract_data
;;     v10 = I64Const ["255"]
;;     v11 = I64And v9, v10
;;       semantic ArithmeticOp: and
;;     v12 = I64Const ["77"]
;;     v13 = I64Eq v11, v12
;;       semantic ComparisonOp: eq
;;     successors: block2, block5
;;     terminator: if v13 then block2(v9) else block5
;;   block block5
;;     terminator: unreachable

;; func func7 (; func7 ;)
;;   calls
;;   func10 -> func10
;;   block block0
;;     Call ["func10"]
;;     terminator: unreachable
;;   block block1
;;     terminator: none

;; func get_count (; func8 ;)
;;   export: get_count
;;   param user: Address
;;   result u32
;;   semantic EntryPoint: Contract entry point `get_count`
;;   semantic StorageGet: ledger::get_contract_data
;;   semantic StorageHas: ledger::has_contract_data
;;   semantic VectorOp: vec::vec_new_from_linear_memory
;;   semantic StringOrSymbolOp: buf::symbol_new_from_linear_memory
;;   semantic ArithmeticOp: add
;;   semantic ArithmeticOp: and
;;   semantic ArithmeticOp: or
;;   semantic ArithmeticOp: shl
;;   semantic ArithmeticOp: shr
;;   semantic ArithmeticOp: sub
;;   semantic ComparisonOp: eq
;;   semantic ComparisonOp: eqz
;;   semantic ComparisonOp: ge
;;   semantic ComparisonOp: lt
;;   semantic ComparisonOp: ne
;;   calls
;;   func0 -> func0
;;   block block0
;;     param v1: i64
;;     v2 = GlobalGet ["global0"]
;;     v3 = I32Const ["16"]
;;     v4 = I32Sub v2, v3
;;       semantic ArithmeticOp: sub
;;     GlobalSet v4 ["global0"]
;;     v6 = I64Const ["255"]
;;     v7 = I64And v1, v6
;;       semantic ArithmeticOp: and
;;     v8 = I64Const ["77"]
;;     v9 = I64Eq v7, v8
;;       semantic ComparisonOp: eq
;;     successors: block2, block3
;;     terminator: if v9 then block2(v1, v4) else block3
;;   block block1
;;     param v0: i64
;;     terminator: return v0
;;   block block2
;;     param v28: i64
;;     param v29: i32
;;     v11 = I32Const ["8"]
;;     v12 = I32Add v29, v11
;;       semantic ArithmeticOp: add
;;     Call v12, v28 ["func0"]
;;     v15 = I32Load v29 ["memory0", "align=2", "offset=8"]
;;     v16 = I64Load32U v29 ["memory0", "align=2", "offset=12"]
;;     v17 = I32Const ["16"]
;;     v18 = I32Add v29, v17
;;       semantic ArithmeticOp: add
;;     GlobalSet v18 ["global0"]
;;     v20 = I64Const ["32"]
;;     v21 = I64Shl v16, v20
;;       semantic ArithmeticOp: shl
;;     v22 = I64Const ["4"]
;;     v23 = I64Or v21, v22
;;       semantic ArithmeticOp: or
;;     v24 = I64Const ["4"]
;;     v25 = I32Const ["1"]
;;     v26 = I32And v15, v25
;;       semantic ArithmeticOp: and
;;     v27 = Select v23, v24, v26
;;     successors: block1
;;     terminator: br block1(v27)
;;   block block3
;;     terminator: unreachable

;; func increment (; func9 ;)
;;   export: increment
;;   param user: Address
;;   result u32
;;   semantic EntryPoint: Contract entry point `increment`
;;   semantic StorageSet: ledger::put_contract_data
;;   semantic StorageGet: ledger::get_contract_data
;;   semantic StorageHas: ledger::has_contract_data
;;   semantic PublishEvent: context::contract_event
;;   semantic AuthOp: address::require_auth
;;   semantic VectorOp: vec::vec_new_from_linear_memory
;;   semantic StringOrSymbolOp: buf::symbol_new_from_linear_memory
;;   semantic ArithmeticOp: add
;;   semantic ArithmeticOp: and
;;   semantic ArithmeticOp: or
;;   semantic ArithmeticOp: shl
;;   semantic ArithmeticOp: shr
;;   semantic ArithmeticOp: sub
;;   semantic ComparisonOp: eq
;;   semantic ComparisonOp: eqz
;;   semantic ComparisonOp: ge
;;   semantic ComparisonOp: lt
;;   semantic ComparisonOp: ne
;;   calls
;;   func10 -> func10
;;   a::0 -> a::0
;;   func0 -> func0
;;   func1 -> func1
;;   l::_ -> l::_
;;   func4 -> func4
;;   x::1 -> x::1
;;   block block0
;;     param v1: i64
;;     v2 = GlobalGet ["global0"]
;;     v3 = I32Const ["48"]
;;     v4 = I32Sub v2, v3
;;       semantic ArithmeticOp: sub
;;     GlobalSet v4 ["global0"]
;;     v6 = I64Const ["255"]
;;     v7 = I64And v1, v6
;;       semantic ArithmeticOp: and
;;     v8 = I64Const ["77"]
;;     v9 = I64Ne v7, v8
;;       semantic ComparisonOp: ne
;;     successors: block3, block4
;;     terminator: if v9 then block3 else block4(v1, v4)
;;   block block1
;;     param v0: i64
;;     terminator: none
;;   block block2
;;     Call ["func10"]
;;     terminator: unreachable
;;   block block3
;;     terminator: unreachable
;;   block block4
;;     param v90: i64
;;     param v91: i32
;;     v11 = Call v90 ["a::0"]
;;       semantic AuthOp: address::require_auth
;;     v13 = I32Const ["8"]
;;     v14 = I32Add v91, v13
;;       semantic ArithmeticOp: add
;;     Call v14, v90 ["func0"]
;;     v16 = I32Const ["0"]
;;     v17 = I32Load v91 ["memory0", "align=2", "offset=12"]
;;     v18 = I32Const ["0"]
;;     v19 = I32Load v91 ["memory0", "align=2", "offset=8"]
;;     v20 = I32Const ["1"]
;;     v21 = I32And v19, v20
;;       semantic ArithmeticOp: and
;;     v22 = Select v17, v18, v21
;;     v23 = I32Const ["-1"]
;;     v24 = I32Eq v22, v23
;;       semantic ComparisonOp: eq
;;     successors: block2, block5
;;     terminator: if v24 then block2 else block5(v90, v91, v16, v22)
;;   block block5
;;     param v92: i64
;;     param v93: i32
;;     param v94: i32
;;     param v95: i32
;;     v25 = I64Const ["0"]
;;     v27 = Call v25, v92 ["func1"]
;;     v29 = I32Const ["1"]
;;     v30 = I32Add v95, v29
;;       semantic ArithmeticOp: add
;;     v31 = I64ExtendI32U v30
;;     v32 = I64Const ["32"]
;;     v33 = I64Shl v31, v32
;;       semantic ArithmeticOp: shl
;;     v34 = I64Const ["4"]
;;     v35 = I64Or v33, v34
;;       semantic ArithmeticOp: or
;;     v36 = I64Const ["1"]
;;     v37 = Call v27, v35, v36 ["l::_"]
;;       semantic StorageSet: ledger::put_contract_data
;;     I64Store v93, v92 ["memory0", "align=3", "offset=24"]
;;     v40 = I64Const ["3372789210509277454"]
;;     I64Store v93, v40 ["memory0", "align=3", "offset=16"]
;;     successors: block6
;;     terminator: br block6(v94, v93, v35)
;;   block block6
;;     param v42: i32
;;     param v63: i32
;;     param v72: i64
;;     v43 = I32Const ["16"]
;;     v44 = I32Ne v42, v43
;;       semantic ComparisonOp: ne
;;     successors: block8, block9
;;     terminator: if v44 then block8(v42, v63, v72) else block9(v63, v72)
;;   block block7
;;     terminator: none
;;   block block8
;;     param v96: i32
;;     param v97: i32
;;     param v98: i64
;;     v79 = I32Const ["32"]
;;     v80 = I32Add v97, v79
;;       semantic ArithmeticOp: add
;;     v82 = I32Add v80, v96
;;       semantic ArithmeticOp: add
;;     v83 = I64Const ["2"]
;;     I64Store v82, v83 ["memory0", "align=3", "offset=0"]
;;     v85 = I32Const ["8"]
;;     v86 = I32Add v96, v85
;;       semantic ArithmeticOp: add
;;     successors: block6
;;     terminator: br block6(v86, v97, v98)
;;   block block9
;;     param v99: i32
;;     param v100: i64
;;     v45 = I32Const ["0"]
;;     successors: block11
;;     terminator: br block11(v45, v99, v100)
;;   block block10
;;     param v101: i32
;;     param v102: i64
;;     v65 = I32Const ["32"]
;;     v66 = I32Add v101, v65
;;       semantic ArithmeticOp: add
;;     v67 = I32Const ["2"]
;;     v68 = Call v66, v67 ["func4"]
;;     v74 = Call v68, v102 ["x::1"]
;;       semantic PublishEvent: context::contract_event
;;     v75 = I32Const ["48"]
;;     v76 = I32Add v101, v75
;;       semantic ArithmeticOp: add
;;     GlobalSet v76 ["global0"]
;;     terminator: return v102
;;   block block11
;;     param v46: i32
;;     param v50: i32
;;     param v70: i64
;;     v47 = I32Const ["16"]
;;     v48 = I32Eq v46, v47
;;       semantic ComparisonOp: eq
;;     successors: block10, block13
;;     terminator: if v48 then block10(v50, v70) else block13(v46, v50, v70)
;;   block block12
;;     terminator: none
;;   block block13
;;     param v103: i32
;;     param v104: i32
;;     param v105: i64
;;     v51 = I32Const ["32"]
;;     v52 = I32Add v104, v51
;;       semantic ArithmeticOp: add
;;     v54 = I32Add v52, v103
;;       semantic ArithmeticOp: add
;;     v55 = I32Const ["16"]
;;     v56 = I32Add v104, v55
;;       semantic ArithmeticOp: add
;;     v57 = I32Add v56, v103
;;       semantic ArithmeticOp: add
;;     v58 = I64Load v57 ["memory0", "align=3", "offset=0"]
;;     I64Store v54, v58 ["memory0", "align=3", "offset=0"]
;;     v60 = I32Const ["8"]
;;     v61 = I32Add v103, v60
;;       semantic ArithmeticOp: add
;;     successors: block11
;;     terminator: br block11(v61, v104, v105)

;; func func10 (; func10 ;)
;;   calls
;;   func11 -> func11
;;   block block0
;;     Call ["func11"]
;;     terminator: unreachable
;;   block block1
;;     terminator: none

;; func func11 (; func11 ;)
;;   block block0
;;     terminator: unreachable
;;   block block1
;;     terminator: none

;; func _ (; func12 ;)
;;   export: _
;;   semantic Dispatcher: Contract dispatch entry point
;;   block block0
;;     successors: block1
;;     terminator: br block1
;;   block block1
;;     terminator: return

