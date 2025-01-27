add_library(LLVMObfuscationx SHARED
        FunctionCallObfuscate.cpp
        CryptoUtils.cpp
        BogusControlFlow.cpp
        SubstituteImpl.cpp
        Substitution.cpp
        Flattening.cpp
        Utils.cpp
        SplitBasicBlocks.cpp
        AntiClassDump.cpp
        AntiDebugging.cpp
        AntiHooking.cpp
        StringEncryption.cpp
        IndirectBranch.cpp
        FunctionWrapper.cpp
        ConstantEncryption.cpp
        Obfuscation.cpp
        )
target_include_directories(LLVMObfuscationx PRIVATE ${CMAKE_SOURCE_DIR}/obfuscation)

add_dependencies(LLVMObfuscationx intrinsics_gen LLVMLinker)

llvm_map_components_to_libnames(llvm_libs core support irreader linker passes)
target_link_libraries(LLVMObfuscationx PRIVATE ${llvm_libs})

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_target_properties(LLVMObfuscationx PROPERTIES
        LINK_FLAGS "-static -static-libgcc -Wl,-Bstatic,--whole-archive -lwinpthread -lstdc++ -Wl,--no-whole-archive -Wl,-Bdynamic"
    )
endif()
execute_process(
        COMMAND git log -1 --format=%H
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        OUTPUT_VARIABLE HIKARI_GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
target_compile_definitions(LLVMObfuscationx PRIVATE "-DGIT_COMMIT_HASH=\"${HIKARI_GIT_COMMIT_HASH}\"")