#include <stddef.h>
#include <dr_api.h>
#include <drmgr.h>
#include <set>
#include <drwrap.h>
#include <drreg.h>
#include <drutil.h>
#include <stdlib.h>
#include <droption.h>
#include <drsyms.h>
#include <drsyscall.h>
#include <drx.h>
#include <string.h>
#include <dr_ir_macros.h>
#ifdef WINDOWS
# include <windows.h>
#endif

#include "yyx_engine.h"
#include "utils.h"

static int client_id = 0;

struct per_thread_t {
	
	std::map<int, int>* op_count;
	
};

static int tls_index = 0;

void
event_thread_init(void* drcontext)
{
	per_thread_t* t_data = (per_thread_t*)dr_thread_alloc(drcontext, sizeof(per_thread_t));

	/* allocate thread private data */
	drmgr_set_tls_field(drcontext, tls_index, t_data);
	
	t_data->op_count = new std::map<int, int>();
}

dr_emit_flags_t
app_instruction_analysis(void* drcontext, void* tag, instrlist_t* bb, bool for_trace,
	bool translating, void** user_data)
{
	return DR_EMIT_DEFAULT;
}

bool first_paddd = false;

static drx_buf_t* temp_reg_value_store_buffer;

static void
test_paddd(void* app_pc)
{
	void* drcontext = dr_get_current_drcontext();
	
	dr_mcontext_t mc;

	dr_get_mcontext(drcontext, &mc);

	byte* instr_app_pc = (byte*) app_pc;

	instr_t instr_decode_by_pc;
	instr_init(drcontext, &instr_decode_by_pc);
	decode(drcontext, instr_app_pc, &instr_decode_by_pc);

	byte* base_addr = (byte*)drx_buf_get_buffer_base(drcontext, temp_reg_value_store_buffer);

	opnd_t src0 = instr_get_src(&instr_decode_by_pc, 0);
	byte barr[64]{0};
	reg_get_value_ex(opnd_get_reg(src0), &mc, barr);

	dr_printf("processing paddd is reg:%d, reg_id:%d\n", opnd_is_reg(src0), opnd_get_reg(src0));
	auto opnd_0_sz = opnd_get_size(src0);
	uint opnd_0_bt_sz = opnd_size_in_bytes(opnd_0_sz);
	for (int i = 0; i < opnd_0_bt_sz; i++) {
		dr_printf("reg_get_value_ex[%d]:%d,", i, barr[i]);
	}
	dr_printf("\n");
	//for (int i = 0; i < opnd_0_bt_sz; i++) {
	//	dr_printf("vmovdqu[%d]:%d,", i, base_addr[i]);
	//}
	//dr_printf("\n");
}

dr_emit_flags_t
app_instruction_val(void* drcontext, void* tag, instrlist_t* bb, instr_t* instr,
	bool for_trace, bool translating, void* user_data)
{
	per_thread_t* t_data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_index);
	
	bool instr_is_app_instr = instr_is_app(instr);
	if (instr_is_app_instr) {
		bool instr_is_not_nop_instr = not instr_is_nop(instr);
		if (instr_is_not_nop_instr) {
			int instr_opcode = instr_get_opcode(instr);
			if (instr_opcode == OP_paddd) {
				if (not first_paddd) {
					//{
					//	bool k0_dead = false;
					//	drreg_status_t k0_ds = drreg_is_register_dead(drcontext, DR_REG_K0, instr, &k0_dead);
					//	dr_printf("at first paddd, k0_dead:%d\n", k0_dead);// true
					//}
					//{
					//	bool k1_dead = false;
					//	drreg_status_t k1_ds = drreg_is_register_dead(drcontext, DR_REG_K1, instr, &k1_dead);
					//	dr_printf("at first paddd, k1_dead:%d\n", k1_dead);// true
					//}
					//{
					//	bool k2_dead = false;
					//	drreg_status_t k2_ds = drreg_is_register_dead(drcontext, DR_REG_K2, instr, &k2_dead);
					//	dr_printf("at first paddd, k2_dead:%d\n", k2_dead);// true
					//}
					void* buf_ptr = drx_buf_get_buffer_base(drcontext, temp_reg_value_store_buffer);
					opnd_t opnd_0 = instr_get_src(instr, 0);
					opnd_size_t o0_sz = opnd_get_size(opnd_0);
					instr_t* new_instr = INSTR_CREATE_vmovdqu(drcontext, opnd_create_abs_addr(buf_ptr, o0_sz), opnd_0);
					// INSTR_CREATE_vmovdqu(drcontext, , s);
					// instr_t* new_instr = XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(buf_ptr, 0), opnd);
					instrlist_meta_preinsert(bb, instr, new_instr);

					app_pc instr_app_pc = instr_get_app_pc(instr);
					dr_insert_clean_call(drcontext, bb, instr, test_paddd, true, 1, OPND_CREATE_INTPTR(instr_app_pc));
				}
				first_paddd = true;
			}
			per_thread_t* t_data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_index);
			//				std::string instr_op_info = get_opcode_name(instr_opcode);
			//				instr_op_info += "," + std::to_string(instr_opcode);
			int ioi_count = 0;
			auto ti_itr = t_data->op_count->find(instr_opcode);// instr_op_info
			if (ti_itr != t_data->op_count->end()) {
				ioi_count = ti_itr->second;
			}
			ioi_count++;
			t_data->op_count->insert_or_assign(instr_opcode, ioi_count);// instr_op_info
		}
	}

	return DR_EMIT_DEFAULT;
}

class YPrintUtil {

public:

	template<typename K, typename V>
	static std::string print_to_string(std::map<K, V>& mp) {
		std::stringstream ss;

		ss << "{";
		for (auto it = mp->begin(); it != mp->end(); it++) {
			ss << "{" << it->first << ":" << it->second << "}" << ",";
		}
		ss << "}";

		return ss.str();
	}

	template<typename V>
	static std::string print_to_string(std::set<V>& st) {
		std::stringstream ss;

		ss << "{";
		for (auto it = st.begin(); it != st.end(); it++) {
			ss << *it << ",";
		}
		ss << "}";

		return ss.str();
	}

};

void CheckAllOpCanHandle(void* drcontext, std::map<int, int>* op_count) {
	// check code
	std::set<std::string> unhandle_ops;
	for (auto it = op_count->begin(); it != op_count->end(); it++) {
		int instr_op_id = it->first;
		auto name = decode_opcode_name(instr_op_id);
		std::string name_str = std::string(name);
		auto op_itr = taint_meta.find(name_str);
		if (op_itr != taint_meta.end()) {
			// do nothing. 
		}
		else {
			unhandle_ops.insert(name_str);
		}
	}
//	if (unhandle_ops.size() > 0) {
		std::string uopss = YPrintUtil::print_to_string<std::string>(unhandle_ops);
		// print to console of the set about the total unhandled for whole trace. 
		dr_printf("=== yyx info: Encounter unhandled opnames:%s.\n", uopss.c_str());

		auto debug_log = log_file_open(client_id, drcontext, NULL /* using curr_dir path */, "instr_val_instrument_debug",
			DR_FILE_CLOSE_ON_FORK | DR_FILE_ALLOW_LARGE);
		FILE* dbg_f = log_stream_from_file(debug_log);
		fprintf(dbg_f, "== print unhandled op begin ==\n");
		fprintf(dbg_f, "unhandled op size:%lld, details:%s.\n", unhandle_ops.size(), uopss.c_str());
		fprintf(dbg_f, "== print unhandled op end ==\n");
		log_stream_close(dbg_f);
//	}
}

void
event_thread_exit(void* drcontext)
{
	per_thread_t* t_data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_index);
	
	CheckAllOpCanHandle(drcontext, t_data->op_count);

	delete t_data->op_count;

	dr_thread_free(drcontext, t_data, sizeof(per_thread_t));

}

static void event_exit(void)
{
	// dr_free_module_data(main_module);
	// dr_printf("event_exit 0 end!\n");
	/*after drx_exit(), drx_ routines cannot be used at all, thus the resources should be freed at the beginning.*/
//	drx_buf_free(GlobalInfo::data_buffer);

	if (!drmgr_unregister_tls_field(tls_index)) DR_ASSERT_MSG(false, "drmgr_unregister_tls_field false");
	if (!drmgr_unregister_thread_init_event(event_thread_init)) DR_ASSERT_MSG(false, "drmgr_unregister_thread_init_event false");
	if (!drmgr_unregister_thread_exit_event(event_thread_exit)) DR_ASSERT_MSG(false, "drmgr_unregister_thread_exit_event false");
	if (!drmgr_unregister_bb_insertion_event(app_instruction_val)) DR_ASSERT_MSG(false, "drmgr_unregister_bb_insertion_event false");
//	dr_printf("event_exit 2 end!\n");
	if (drreg_exit() != DRREG_SUCCESS) DR_ASSERT_MSG(false, "drreg_exit false");
	if (drsys_exit() != DRMF_SUCCESS) DR_ASSERT_MSG(false, "drsys_exit false");
	drx_exit();
	drwrap_exit();
	drmgr_exit();
//	dr_printf("event_exit 3 end!\n");
	drutil_exit();
//	dr_printf("event_exit 4 end!\n");
//	dr_printf("event_exit 5 end!\n");
//	dr_printf("event_exit end!\n");
}

void dr_client_main(client_id_t id, int argc, const char* argv[])
{
	dr_set_client_name("yyx_pre_analysis", "yangyixiaofirst@outlook.com");

	dr_printf("=== begin pre analysis\n");

//	opnd_size_t osz_sz = reg_get_size(DR_REG_K0);
//	int osz_byte_sz = opnd_size_in_bytes(osz_sz);
//	dr_printf("osz_byte_sz:%d\n", osz_byte_sz);

	client_id = id;

	std::string parse_err;
	int last_index;
	if (!dynamorio::droption::droption_parser_t::parse_argv(dynamorio::droption::DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_index)) {
		dr_abort();
	}

	drsys_options_t sys_ops = { sizeof(sys_ops), 0, };
	drmf_status_t res = drsys_init(id, &sys_ops);

#ifdef WINDOWS
	if (res == DRMF_WARNING_UNSUPPORTED_KERNEL) {
		dr_os_version_info_t os_version = { sizeof(os_version), };
		dr_get_os_version(&os_version);
		dr_printf("=== yyx_pre_analysis client info: Currently may not support WinKernel: %s ===\n", os_version.release_id);
//		ASSERT(false, "drsys failed to init, unsupported kernel.");
	}
#endif
	
	drreg_options_t ops = {
			.struct_size = sizeof(drreg_options_t),
			.num_spill_slots = 4,
			.conservative = false
	};
	
	if (!drmgr_init()) DR_ASSERT_MSG(false, "drmgr_init false");
	if (!drwrap_init()) DR_ASSERT_MSG(false, "drwrap_init false");
	if (!drutil_init()) DR_ASSERT_MSG(false, "drutil_init false");
	if (!drx_init()) DR_ASSERT_MSG(false, "drx_init false");
	if (drreg_init(&ops) != DRREG_SUCCESS) DR_ASSERT_MSG(false, "drreg_init false");

	dr_register_exit_event(event_exit);
	if (!drmgr_register_thread_init_event(event_thread_init)) DR_ASSERT_MSG(false, "drmgr_register_thread_init_event false");
	if (!drmgr_register_thread_exit_event(event_thread_exit)) DR_ASSERT_MSG(false, "drmgr_register_thread_exit_event false");
	
	if (!drmgr_register_bb_instrumentation_event(app_instruction_analysis, app_instruction_val, NULL)) DR_ASSERT_MSG(false, "drmgr_register_bb_instrumentation_event false");
	tls_index = drmgr_register_tls_field();

	temp_reg_value_store_buffer = drx_buf_create_circular_buffer(512 / 8 * 8 * 5);
}


