#ifndef MPT3SAS_BASE_H_INCLUDED
#define MPT3SAS_BASE_H_INCLUDED
#include "mpi/mpi2_type.h"
#include "mpi/mpi2.h"
#include "mpi/mpi2_ioc.h"
#include "mpi/mpi2_cnfg.h"
#include "mpi/mpi2_init.h"
#include "mpi/mpi2_sas.h"
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_transport_sas.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_eh.h>
#include <linux/pci.h>
#define MPT3SAS_DRIVER_NAME		"mpt3sas"
#define MPT3SAS_AUTHOR "Avago Technologies <MPT-FusionLinux.pdl@avagotech.com>"
#define MPT3SAS_DESCRIPTION	"LSI MPT Fusion SAS 3.0 Device Driver"
#define MPT3SAS_DRIVER_VERSION		"39.100.00.00"
#define MPT3SAS_MAJOR_VERSION		39
#define MPT3SAS_MINOR_VERSION		100
#define MPT3SAS_BUILD_VERSION		0
#define MPT3SAS_RELEASE_VERSION	00
#define MPT3SAS_DEFAULT_COREDUMP_TIMEOUT_SECONDS	(15) 
#define MPT3SAS_COREDUMP_LOOP_DONE                     (0xFF)
#define MPT3SAS_TIMESYNC_TIMEOUT_SECONDS		(10) 
#define MPT3SAS_TIMESYNC_UPDATE_INTERVAL		(900) 
#define MPT3SAS_TIMESYNC_UNIT_MASK			(0x80) 
#define MPT3SAS_TIMESYNC_MASK				(0x7F) 
#define SECONDS_PER_MIN					(60)
#define SECONDS_PER_HOUR				(3600)
#define MPT3SAS_COREDUMP_LOOP_DONE			(0xFF)
#define MPI26_SET_IOC_PARAMETER_SYNC_TIMESTAMP		(0x81)
#define MPT_MAX_PHYS_SEGMENTS	SG_CHUNK_SIZE
#define MPT_MIN_PHYS_SEGMENTS	16
#define MPT_KDUMP_MIN_PHYS_SEGMENTS	32
#define MCPU_MAX_CHAINS_PER_IO	3
#ifdef CONFIG_SCSI_MPT3SAS_MAX_SGE
#define MPT3SAS_SG_DEPTH		CONFIG_SCSI_MPT3SAS_MAX_SGE
#else
#define MPT3SAS_SG_DEPTH		MPT_MAX_PHYS_SEGMENTS
#endif
#ifdef CONFIG_SCSI_MPT2SAS_MAX_SGE
#define MPT2SAS_SG_DEPTH		CONFIG_SCSI_MPT2SAS_MAX_SGE
#else
#define MPT2SAS_SG_DEPTH		MPT_MAX_PHYS_SEGMENTS
#endif
#define MPT3SAS_SATA_QUEUE_DEPTH	32
#define MPT3SAS_SAS_QUEUE_DEPTH		254
#define MPT3SAS_RAID_QUEUE_DEPTH	128
#define MPT3SAS_KDUMP_SCSI_IO_DEPTH	200
#define MPT3SAS_RAID_MAX_SECTORS	8192
#define MPT3SAS_HOST_PAGE_SIZE_4K	12
#define MPT3SAS_NVME_QUEUE_DEPTH	128
#define MPT_NAME_LENGTH			32	
#define MPT_STRING_LENGTH		64
#define MPI_FRAME_START_OFFSET		256
#define REPLY_FREE_POOL_SIZE		512 
#define MPT_MAX_CALLBACKS		32
#define INTERNAL_CMDS_COUNT		10	
#define INTERNAL_SCSIIO_CMDS_COUNT	3
#define MPI3_HIM_MASK			0xFFFFFFFF 
#define MPT3SAS_INVALID_DEVICE_HANDLE	0xFFFF
#define MAX_CHAIN_ELEMT_SZ		16
#define DEFAULT_NUM_FWCHAIN_ELEMTS	8
#define IO_UNIT_CONTROL_SHUTDOWN_TIMEOUT 6
#define FW_IMG_HDR_READ_TIMEOUT	15
#define IOC_OPERATIONAL_WAIT_COUNT	10
#define ioc_err(ioc, fmt, ...)						\
	pr_err("%s: " fmt, (ioc)->name, ##__VA_ARGS__)
#define ioc_notice(ioc, fmt, ...)					\
	pr_notice("%s: " fmt, (ioc)->name, ##__VA_ARGS__)
#define ioc_warn(ioc, fmt, ...)						\
	pr_warn("%s: " fmt, (ioc)->name, ##__VA_ARGS__)
#define ioc_info(ioc, fmt, ...)						\
	pr_info("%s: " fmt, (ioc)->name, ##__VA_ARGS__)
#define MPT_TARGET_FLAGS_DELETED	0x04
#define MPT_TARGET_FASTPATH_IO		0x08
#define SAS2_PCI_DEVICE_B0_REVISION	(0x01)
#define SAS3_PCI_DEVICE_C0_REVISION	(0x02)
#define MAX_COMBINED_MSIX_VECTORS(gen35) ((gen35 == 1) ? 16 : 8)
#define MPT3_SUP_REPLY_POST_HOST_INDEX_REG_COUNT_G3	12
#define MPT3_SUP_REPLY_POST_HOST_INDEX_REG_COUNT_G35	16
#define MPT3_SUP_REPLY_POST_HOST_INDEX_REG_OFFSET	(0x10)
#define MPT3_MIN_IRQS					1
#define MFG10_OEM_ID_INVALID                   (0x00000000)
#define MFG10_OEM_ID_DELL                      (0x00000001)
#define MFG10_OEM_ID_FSC                       (0x00000002)
#define MFG10_OEM_ID_SUN                       (0x00000003)
#define MFG10_OEM_ID_IBM                       (0x00000004)
#define MFG10_GF0_OCE_DISABLED                 (0x00000001)
#define MFG10_GF0_R1E_DRIVE_COUNT              (0x00000002)
#define MFG10_GF0_R10_DISPLAY                  (0x00000004)
#define MFG10_GF0_SSD_DATA_SCRUB_DISABLE       (0x00000008)
#define MFG10_GF0_SINGLE_DRIVE_R0              (0x00000010)
#define VIRTUAL_IO_FAILED_RETRY			(0x32010081)
#define MPT3SAS_DEVICE_HIGH_IOPS_DEPTH		8
#define MPT3SAS_HIGH_IOPS_REPLY_QUEUES		8
#define MPT3SAS_HIGH_IOPS_BATCH_COUNT		16
#define MPT3SAS_GEN35_MAX_MSIX_QUEUES		128
#define RDPQ_MAX_INDEX_IN_ONE_CHUNK		16
struct Mpi2ManufacturingPage10_t {
	MPI2_CONFIG_PAGE_HEADER	Header;		
	U8	OEMIdentifier;			
	U8	Reserved1;			
	U16	Reserved2;			
	U32	Reserved3;			
	U32	GenericFlags0;			
	U32	GenericFlags1;			
	U32	Reserved4;			
	U32	OEMSpecificFlags0;		
	U32	OEMSpecificFlags1;		
	U32	Reserved5[18];			
};
struct Mpi2ManufacturingPage11_t {
	MPI2_CONFIG_PAGE_HEADER Header;		
	__le32	Reserved1;			
	u8	Reserved2;			
	u8	EEDPTagMode;			
	u8	Reserved3;			
	u8	Reserved4;			
	__le32	Reserved5[8];			
	u16	AddlFlags2;			
	u8	AddlFlags3;			
	u8	Reserved6;			
	__le32	Reserved7[7];			
	u8	NVMeAbortTO;			
	u8	NumPerDevEvents;		
	u8	HostTraceBufferDecrementSizeKB;	
	u8	HostTraceBufferFlags;		
	u16	HostTraceBufferMaxSizeKB;	
	u16	HostTraceBufferMinSizeKB;	
	u8	CoreDumpTOSec;			
	u8	TimeSyncInterval;		
	u16	Reserved9;			
	__le32	Reserved10;			
};
struct MPT3SAS_TARGET {
	struct scsi_target *starget;
	u64	sas_address;
	struct _raid_device *raid_device;
	u16	handle;
	int	num_luns;
	u32	flags;
	u8	deleted;
	u8	tm_busy;
	struct hba_port *port;
	struct _sas_device *sas_dev;
	struct _pcie_device *pcie_dev;
};
#define MPT_DEVICE_FLAGS_INIT		0x01
#define MFG_PAGE10_HIDE_SSDS_MASK	(0x00000003)
#define MFG_PAGE10_HIDE_ALL_DISKS	(0x00)
#define MFG_PAGE10_EXPOSE_ALL_DISKS	(0x01)
#define MFG_PAGE10_HIDE_IF_VOL_PRESENT	(0x02)
struct MPT3SAS_DEVICE {
	struct MPT3SAS_TARGET *sas_target;
	unsigned int	lun;
	u32	flags;
	u8	configured_lun;
	u8	block;
	u8	tlr_snoop_check;
	u8	ignore_delay_remove;
	u8	ncq_prio_enable;
	unsigned long ata_command_pending;
};
#define MPT3_CMD_NOT_USED	0x8000	
#define MPT3_CMD_COMPLETE	0x0001	
#define MPT3_CMD_PENDING	0x0002	
#define MPT3_CMD_REPLY_VALID	0x0004	
#define MPT3_CMD_RESET		0x0008	
#define MPT3_CMD_COMPLETE_ASYNC 0x0010  
struct _internal_cmd {
	struct mutex mutex;
	struct completion done;
	void	*reply;
	void	*sense;
	u16	status;
	u16	smid;
};
struct _sas_device {
	struct list_head list;
	struct scsi_target *starget;
	u64	sas_address;
	u64	device_name;
	u16	handle;
	u64	sas_address_parent;
					u32	device_info;
	int	id;
	int	channel;
	u16	slot;
	u8	phy;
	u8	responding;
	u8	fast_path;
	u8	pfa_led_on;
	u8	pend_sas_rphy_add;
		u8	chassis_slot;
	u8	is_chassis_slot_valid;
	u8	connector_name[5];
	struct kref refcount;
	u8	port_type;
	struct hba_port *port;
	struct sas_rphy *rphy;
};
static inline void sas_device_get(struct _sas_device *s)
{
	kref_get(&s->refcount);
}
static inline void sas_device_free(struct kref *r)
{
	kfree(container_of(r, struct _sas_device, refcount));
}
static inline void sas_device_put(struct _sas_device *s)
{
	kref_put(&s->refcount, sas_device_free);
}
#define MPT_MAX_WARPDRIVE_PDS		8
struct _sas_port {
	struct list_head port_list;
	u8	num_phys;
	struct sas_identify remote_identify;
	struct sas_rphy *rphy;
	struct sas_port *port;
	struct hba_port *hba_port;
	struct list_head phy_list;
};
struct _sas_phy {
	struct list_head port_siblings;
	struct sas_identify identify;
	struct sas_identify remote_identify;
	struct sas_phy *phy;
	u8	phy_id;
	u16	handle;
	u16	attached_handle;
	u8	phy_belongs_to_port;
	u8	hba_vphy;
	struct hba_port *port;
};
struct _sas_node {
	struct list_head list;
	struct device *parent_dev;
	u8	num_phys;
	u64	sas_address;
	u16	handle;
	u64	sas_address_parent;
			u8	responding;
	struct hba_port *port;
	struct	_sas_phy *phy;
	struct list_head sas_port_list;
	struct sas_rphy *rphy;
};
enum reset_type {
	FORCE_BIG_HAMMER,
	SOFT_RESET,
};
struct chain_tracker {
	void *chain_buffer;
	dma_addr_t chain_buffer_dma;
};
struct chain_lookup {
	struct chain_tracker *chains_per_smid;
	atomic_t	chain_offset;
};
struct scsiio_tracker {
	u16	smid;
	struct scsi_cmnd *scmd;
	u8	cb_idx;
	u8	direct_io;
		struct list_head chain_list;
	u16     msix_io;
};
struct request_tracker {
	u16	smid;
	u8	cb_idx;
	struct list_head tracker_list;
};
struct _tr_list {
	struct list_head list;
	u16	handle;
	u16	state;
};
struct _sc_list {
	struct list_head list;
	u16     handle;
};
struct _event_ack_list {
	struct list_head list;
	U16     Event;
	U32     EventContext;
};
struct adapter_reply_queue {
	struct MPT3SAS_ADAPTER	*ioc;
	u8			msix_index;
	u32			reply_post_host_index;
	Mpi2ReplyDescriptorsUnion_t *reply_post_free;
	char			name[MPT_NAME_LENGTH];
	atomic_t		busy;
	u32			os_irq;
		bool			irq_poll_scheduled;
	bool			irq_line_enable;
	bool			is_iouring_poll_q;
	struct list_head	list;
};
typedef void (*MPT_ADD_SGE)(void *paddr, u32 flags_length, dma_addr_t dma_addr);
typedef int (*MPT_BUILD_SG_SCMD)(struct MPT3SAS_ADAPTER *ioc,
	struct scsi_cmnd *scmd, u16 smid);typedef void (*MPT_BUILD_SG)(struct MPT3SAS_ADAPTER *ioc, void *psge,
		dma_addr_t data_out_dma, size_t data_out_sz,
		dma_addr_t data_in_dma, size_t data_in_sz);
typedef void (*MPT_BUILD_ZERO_LEN_SGE)(struct MPT3SAS_ADAPTER *ioc,
		void *paddr);
typedef void (*PUT_SMID_IO_FP_HIP) (struct MPT3SAS_ADAPTER *ioc, u16 smid,
	u16 funcdep);
typedef void (*PUT_SMID_DEFAULT) (struct MPT3SAS_ADAPTER *ioc, u16 smid);
typedef u32 (*BASE_READ_REG) (const volatile void __iomem *addr);
typedef u8 (*GET_MSIX_INDEX) (struct MPT3SAS_ADAPTER *ioc,
	struct scsi_cmnd *scmd);
union mpi3_version_union {
	MPI2_VERSION_STRUCT		Struct;
	u32				Word;
};
struct mpt3sas_facts {
	u16			MsgVersion;
	u16			HeaderVersion;
	u8			IOCNumber;
	u8			VP_ID;
	u8			VF_ID;
	u16			IOCExceptions;
	u16			IOCStatus;
	u32			IOCLogInfo;
	u8			MaxChainDepth;
	u8			WhoInit;
	u8			NumberOfPorts;
	u8			MaxMSIxVectors;
	u16			RequestCredit;
	u16			ProductID;
	u32			IOCCapabilities;
	union mpi3_version_union	FWVersion;
	u16			IOCRequestFrameSize;
	u16			IOCMaxChainSegmentSize;
	u16			MaxInitiators;
	u16			MaxTargets;
	u16			MaxSasExpanders;
	u16			MaxEnclosures;
	u16			ProtocolFlags;
	u16			HighPriorityCredit;
	u16			MaxReplyDescriptorPostQueueDepth;
	u8			ReplyFrameSize;
	u8			MaxVolumes;
	u16			MaxDevHandle;
	u16			MaxPersistentEntries;
	u16			MinDevHandle;
	u8			CurrentHostPageSize;
};
struct mpt3sas_port_facts {
	u8			PortNumber;
	u8			VP_ID;
	u8			VF_ID;
	u8			PortType;
	u16			MaxPostedCmdBuffers;
};
struct reply_post_struct {
	Mpi2ReplyDescriptorsUnion_t	*reply_post_free;
	dma_addr_t			reply_post_free_dma;
};
struct virtual_phy {
	struct	list_head list;
	u64	sas_address;
	u32	phy_mask;
	u8	flags;
};
#define MPT_VPHY_FLAG_DIRTY_PHY	0x01
struct hba_port {
	struct list_head list;
	u64	sas_address;
	u32	phy_mask;
	u8      port_id;
	u8	flags;
	u32	vphys_mask;
	struct list_head vphys_list;
};
#define HBA_PORT_FLAG_DIRTY_PORT       0x01
#define HBA_PORT_FLAG_NEW_PORT         0x02
#define MULTIPATH_DISABLED_PORT_ID     0xFF
#define MPT3_DIAG_BUFFER_NOT_RELEASED	(0x00)
#define MPT3_DIAG_BUFFER_RELEASED	(0x01)
#define MPT3_DIAG_BUFFER_REL_IOCTL	(0x02 | MPT3_DIAG_BUFFER_RELEASED)
#define MPT3_DIAG_BUFFER_REL_TRIGGER	(0x04 | MPT3_DIAG_BUFFER_RELEASED)
#define MPT3_DIAG_BUFFER_REL_SYSFS	(0x08 | MPT3_DIAG_BUFFER_RELEASED)
#define MPT_DIAG_RESET_ISSUED_BY_DRIVER 0x00000000
#define MPT_DIAG_RESET_ISSUED_BY_USER	0x00000001
typedef void (*MPT3SAS_FLUSH_RUNNING_CMDS)(struct MPT3SAS_ADAPTER *ioc);
struct MPT3SAS_ADAPTER {
	struct list_head list;
	struct Scsi_Host *shost;
	u8		id;
	int		cpu_count;
	char		name[MPT_NAME_LENGTH];
	char		driver_name[MPT_NAME_LENGTH - 8];
		struct pci_dev	*pdev;
	Mpi2SystemInterfaceRegs_t __iomem *chip;
	phys_addr_t	chip_phys;
				int		bars;
	u8		mask_interrupts;
	char		firmware_event_name[20];
	struct workqueue_struct	*firmware_event_thread;
	spinlock_t	fw_event_lock;
	struct list_head fw_event_list;
	struct fw_event_work	*current_event;
	u8		fw_events_cleanup;
				u8		shost_recovery;
		spinlock_t	ioc_reset_in_progress_lock;
	u8		ioc_link_reset_in_progress;
		u8		remove_host;
	u8		pci_error_recovery;
	u8		wait_for_discovery_to_complete;
	u8		is_driver_loading;
	u8		port_enable_failed;
	u8		start_scan;
	u16		start_scan_failed;
	u8		msix_enable;
	u16		msix_vector_count;
	u8		*cpu_msix_table;
	u16		cpu_msix_table_sz;
	resource_size_t __iomem **reply_post_host_index;
					u32		timestamp_update_count;
	u32		time_sync_interval;
				u16		thresh_hold;
	u8		high_iops_queues;
	u8		iopoll_q_start_index;
	u32             drv_internal_flags;
		u32             dma_mask;
	bool		enable_sdev_max_qd;
	bool		use_32bit_dma;
	u8		scsi_io_cb_idx;
	u8		tm_cb_idx;
	u8		transport_cb_idx;
			u8		base_cb_idx;
	u8		port_enable_cb_idx;
	u8		config_cb_idx;
	u8		tm_tr_cb_idx;
		u8		tm_sas_control_cb_idx;
	struct _internal_cmd base_cmds;
	struct _internal_cmd port_enable_cmds;
	struct _internal_cmd transport_cmds;
	struct _internal_cmd scsih_cmds;
	struct _internal_cmd tm_cmds;
	struct _internal_cmd ctl_cmds;
	struct _internal_cmd config_cmds;
	MPT_ADD_SGE	base_add_sg_single;
	MPT_BUILD_SG_SCMD build_sg_scmd;
	MPT_BUILD_SG    build_sg;
	MPT_BUILD_ZERO_LEN_SGE build_zero_len_sge;
	u16             sge_size_ieee;
	u16		hba_mpi_version_belonged;
	MPT_BUILD_SG    build_sg_mpi;
	MPT_BUILD_ZERO_LEN_SGE build_zero_len_sge_mpi;
		u32		event_context;
		u32		event_masks[MPI2_EVENT_NOTIFY_EVENTMASK_WORDS];
		u8		nvme_abort_timeout;
		u16		max_wideport_qd;
	u16		max_narrowport_qd;
	u16		max_nvme_qd;
	u8		max_sata_qd;
	struct mpt3sas_facts facts;
					struct Mpi2ManufacturingPage11_t manu_pg11;
				Mpi2IOUnitPage0_t iounit_pg0;
	Mpi2IOUnitPage1_t iounit_pg1;
	Mpi2IOUnitPage8_t iounit_pg8;
	struct _sas_node sas_hba;
			spinlock_t	sas_node_lock;
	struct list_head sas_device_list;
	struct list_head sas_device_init_list;
	spinlock_t	sas_device_lock;
					int		sas_id;
	int		pcie_target_id;
	void		*blocking_handles;
	void		*pd_handles;
	u16		pd_handles_sz;
	void		*pend_os_device_add;
	u16		pend_os_device_add_sz;
	u16		config_page_sz;
	void		*config_page; 	dma_addr_t	config_page_dma;
	void		*config_vaddr;
	u16		hba_queue_depth;
	u16		sge_size;
	u16		scsiio_depth;
	u16		request_sz;
	u8		*request;
	dma_addr_t	request_dma;
	u32		request_dma_sz;
	struct pcie_sg_list *pcie_sg_lookup;
	spinlock_t	scsi_lookup_lock;
	int		pending_io_count;
	wait_queue_head_t reset_wq;
	u16		*io_queue_num;
	u32		page_size;
	struct chain_lookup *chain_lookup;
	struct list_head free_chain_list;
	struct dma_pool *chain_dma_pool;
	ulong		chain_pages;
	u16		max_sges_in_main_message;
	u16		max_sges_in_chain_message;
	u16		chains_needed_per_io;
	u32		chain_depth;
	u16		chain_segment_sz;
	u16		chains_per_prp_buffer;
	u16		hi_priority_smid;
	u8		*hi_priority;
	dma_addr_t	hi_priority_dma;
	u16		hi_priority_depth;
	struct request_tracker *hpr_lookup;
	struct list_head hpr_free_list;
	u16		internal_smid;
	u8		*internal;
	dma_addr_t	internal_dma;
	u16		internal_depth;
	struct request_tracker *internal_lookup;
	struct list_head internal_free_list;
	u8		*sense;
	dma_addr_t	sense_dma;
	struct dma_pool *sense_dma_pool;
	u16		reply_sz;
	u8		*reply;
	dma_addr_t	reply_dma;
	u32		reply_dma_max_address;
	u32		reply_dma_min_address;
	struct dma_pool *reply_dma_pool;
	u16		reply_free_queue_depth;
	__le32		*reply_free;
	dma_addr_t	reply_free_dma;
	struct dma_pool *reply_free_dma_pool;
	u32		reply_free_host_index;
	u16		reply_post_queue_depth;
	struct reply_post_struct *reply_post;
	u8		rdpq_array_capable;
	u8		rdpq_array_enable;
		struct dma_pool *reply_post_free_dma_pool;
				u8		reply_queue_count;
	struct list_head reply_queue_list;
	u8		combined_reply_queue;
	u8		combined_reply_index_count;
	u8		smp_affinity_enable;
	resource_size_t	**replyPostRegisterIndex;
			struct list_head delayed_sc_list;
	struct list_head delayed_event_ack_list;
	u8		temp_sensors_count;
	struct mutex pci_access_mutex;
															u8		mfg_pg10_hide_flag;
	u8		hide_drives;
				BASE_READ_REG	base_readl;
						void		*device_remove_in_progress;
	u16		device_remove_in_progress_sz;
	u8		is_gen35_ioc;
	u8		is_aero_ioc;
			PUT_SMID_IO_FP_HIP put_smid_scsi_io;
	PUT_SMID_IO_FP_HIP put_smid_fast_path;
	PUT_SMID_IO_FP_HIP put_smid_hi_priority;
	PUT_SMID_DEFAULT put_smid_default;
	GET_MSIX_INDEX get_msix_index_for_smlio;
	u8		multipath_on_hba;
	struct list_head port_table_list;
};
#define MPT_DRV_INTERNAL_FIRST_PE_ISSUED		0x00000001
typedef u8 (*MPT_CALLBACK)(struct MPT3SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
	u32 reply);
extern struct list_head mpt3sas_ioc_list;
extern char    driver_name[MPT_NAME_LENGTH];
extern spinlock_t gioc_lock;
int mpt3sas_base_attach(struct MPT3SAS_ADAPTER *ioc);
void mpt3sas_base_detach(struct MPT3SAS_ADAPTER *ioc);
int mpt3sas_base_map_resources(struct MPT3SAS_ADAPTER *ioc);
void mpt3sas_base_free_resources(struct MPT3SAS_ADAPTER *ioc);
void *mpt3sas_base_get_msg_frame(struct MPT3SAS_ADAPTER *ioc, u16 smid);
void *mpt3sas_base_get_sense_buffer(struct MPT3SAS_ADAPTER *ioc, u16 smid);
__le32 mpt3sas_base_get_sense_buffer_dma(struct MPT3SAS_ADAPTER *ioc,
	u16 smid);
void mpt3sas_base_sync_reply_irqs(struct MPT3SAS_ADAPTER *ioc, u8 poll);
void mpt3sas_base_mask_interrupts(struct MPT3SAS_ADAPTER *ioc);
void mpt3sas_base_unmask_interrupts(struct MPT3SAS_ADAPTER *ioc);
void mpt3sas_base_put_smid_fast_path(struct MPT3SAS_ADAPTER *ioc, u16 smid,
	u16 handle);
void mpt3sas_base_put_smid_hi_priority(struct MPT3SAS_ADAPTER *ioc, u16 smid,
	u16 msix_task);
void mpt3sas_base_put_smid_nvme_encap(struct MPT3SAS_ADAPTER *ioc, u16 smid);
void mpt3sas_base_put_smid_default(struct MPT3SAS_ADAPTER *ioc, u16 smid);
u16 mpt3sas_base_get_smid_hpr(struct MPT3SAS_ADAPTER *ioc, u8 cb_idx);
u16 mpt3sas_base_get_smid_scsiio(struct MPT3SAS_ADAPTER *ioc, u8 cb_idx,
		struct scsi_cmnd *scmd);
void mpt3sas_base_clear_st(struct MPT3SAS_ADAPTER *ioc,
		struct scsiio_tracker *st);
u16 mpt3sas_base_get_smid(struct MPT3SAS_ADAPTER *ioc, u8 cb_idx);
void mpt3sas_base_free_smid(struct MPT3SAS_ADAPTER *ioc, u16 smid);
void mpt3sas_base_initialize_callback_handler(void);
u8 mpt3sas_base_register_callback_handler(MPT_CALLBACK cb_func);
void mpt3sas_base_release_callback_handler(u8 cb_idx);
u8 mpt3sas_base_done(struct MPT3SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
	u32 reply);
u8 mpt3sas_port_enable_done(struct MPT3SAS_ADAPTER *ioc, u16 smid,
	u8 msix_index, u32 reply);
void *mpt3sas_base_get_reply_virt_addr(struct MPT3SAS_ADAPTER *ioc,
	u32 phys_addr);
u32 mpt3sas_base_get_iocstate(struct MPT3SAS_ADAPTER *ioc, int cooked);
void mpt3sas_halt_firmware(struct MPT3SAS_ADAPTER *ioc);
int mpt3sas_port_enable(struct MPT3SAS_ADAPTER *ioc);
u8 mpt3sas_base_check_cmd_timeout(struct MPT3SAS_ADAPTER *ioc,
	u8 status, void *mpi_request, int sz);
#define mpt3sas_check_cmd_timeout(ioc, status, mpi_request, sz, issue_reset) \
do {	ioc_err(ioc, "In func: %s\n", __func__); \
	issue_reset = mpt3sas_base_check_cmd_timeout(ioc, \
	status, mpi_request, sz); } while (0)
int mpt3sas_wait_for_ioc(struct MPT3SAS_ADAPTER *ioc, int wait_count);
int mpt3sas_base_make_ioc_ready(struct MPT3SAS_ADAPTER *ioc, enum reset_type type);
void mpt3sas_base_free_irq(struct MPT3SAS_ADAPTER *ioc);
void mpt3sas_base_disable_msix(struct MPT3SAS_ADAPTER *ioc);
struct scsi_cmnd *mpt3sas_scsih_scsi_lookup_get(struct MPT3SAS_ADAPTER *ioc,
	u16 smid);
u8 mpt3sas_scsih_event_callback(struct MPT3SAS_ADAPTER *ioc, u8 msix_index,
	u32 reply);
void mpt3sas_scsih_set_tm_flag(struct MPT3SAS_ADAPTER *ioc, u16 handle);
void mpt3sas_scsih_clear_tm_flag(struct MPT3SAS_ADAPTER *ioc, u16 handle);
void mpt3sas_device_remove_by_sas_address(struct MPT3SAS_ADAPTER *ioc,
	u64 sas_address, struct hba_port *port);
u8 mpt3sas_check_for_pending_internal_cmds(struct MPT3SAS_ADAPTER *ioc,
	u16 smid);
struct hba_port *
mpt3sas_get_port_by_id(struct MPT3SAS_ADAPTER *ioc, u8 port,
	u8 bypass_dirty_port_flag);
struct _sas_device *mpt3sas_get_sdev_by_addr(
	 struct MPT3SAS_ADAPTER *ioc, u64 sas_address,
	 struct hba_port *port);
struct _sas_device *__mpt3sas_get_sdev_by_addr(
	 struct MPT3SAS_ADAPTER *ioc, u64 sas_address,
	 struct hba_port *port);
struct _sas_device *mpt3sas_get_sdev_by_handle(struct MPT3SAS_ADAPTER *ioc,
	u16 handle);
struct _pcie_device *mpt3sas_get_pdev_by_handle(struct MPT3SAS_ADAPTER *ioc,
	u16 handle);
void mpt3sas_port_enable_complete(struct MPT3SAS_ADAPTER *ioc);
struct _raid_device *
mpt3sas_raid_device_find_by_handle(struct MPT3SAS_ADAPTER *ioc, u16 handle);
void mpt3sas_scsih_change_queue_depth(struct scsi_device *sdev, int qdepth);
struct _sas_device *
__mpt3sas_get_sdev_by_rphy(struct MPT3SAS_ADAPTER *ioc, struct sas_rphy *rphy);
struct virtual_phy *
mpt3sas_get_vphy_by_phy(struct MPT3SAS_ADAPTER *ioc,
	struct hba_port *port, u32 phy);
u8 mpt3sas_config_done(struct MPT3SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
	u32 reply);
int mpt3sas_config_get_number_hba_phys(struct MPT3SAS_ADAPTER *ioc,
	u8 *num_phys);
int mpt3sas_config_get_manufacturing_pg0(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2ManufacturingPage0_t *config_page);
int mpt3sas_config_get_manufacturing_pg11(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply,
	struct Mpi2ManufacturingPage11_t  *config_page);
int mpt3sas_config_set_manufacturing_pg11(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply,
	struct Mpi2ManufacturingPage11_t *config_page);
int mpt3sas_config_get_iounit_pg0(struct MPT3SAS_ADAPTER *ioc, Mpi2ConfigReply_t
	*mpi_reply, Mpi2IOUnitPage0_t *config_page);
int mpt3sas_config_get_sas_device_pg0(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2SasDevicePage0_t *config_page,
	u32 form, u32 handle);
int mpt3sas_config_get_sas_iounit_pg0(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2SasIOUnitPage0_t *config_page,
	u16 sz);
int mpt3sas_config_get_iounit_pg1(struct MPT3SAS_ADAPTER *ioc, Mpi2ConfigReply_t
	*mpi_reply, Mpi2IOUnitPage1_t *config_page);
int mpt3sas_config_set_iounit_pg1(struct MPT3SAS_ADAPTER *ioc, Mpi2ConfigReply_t
	*mpi_reply, Mpi2IOUnitPage1_t *config_page);
int mpt3sas_config_get_iounit_pg8(struct MPT3SAS_ADAPTER *ioc, Mpi2ConfigReply_t
	*mpi_reply, Mpi2IOUnitPage8_t *config_page);
int mpt3sas_config_get_sas_iounit_pg1(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2SasIOUnitPage1_t *config_page,
	u16 sz);
int mpt3sas_config_set_sas_iounit_pg1(struct MPT3SAS_ADAPTER *ioc,
	Mpi2ConfigReply_t *mpi_reply, Mpi2SasIOUnitPage1_t *config_page,
	u16 sz);
int mpt3sas_config_get_ioc_pg8(struct MPT3SAS_ADAPTER *ioc, Mpi2ConfigReply_t
	*mpi_reply, Mpi2IOCPage8_t *config_page);
int mpt3sas_config_get_phy_pg0(struct MPT3SAS_ADAPTER *ioc, Mpi2ConfigReply_t
	*mpi_reply, Mpi2SasPhyPage0_t *config_page, u32 phy_number);
int mpt3sas_config_get_phy_pg1(struct MPT3SAS_ADAPTER *ioc, Mpi2ConfigReply_t
	*mpi_reply, Mpi2SasPhyPage1_t *config_page, u32 phy_number);
extern struct scsi_transport_template *mpt3sas_transport_template;
u8 mpt3sas_transport_done(struct MPT3SAS_ADAPTER *ioc, u16 smid, u8 msix_index,
	u32 reply);
struct _sas_port *mpt3sas_transport_port_add(struct MPT3SAS_ADAPTER *ioc,
	u16 handle, u64 sas_address, struct hba_port *port);
void mpt3sas_transport_port_remove(struct MPT3SAS_ADAPTER *ioc, u64 sas_address,
	u64 sas_address_parent, struct hba_port *port);
int mpt3sas_transport_add_host_phy(struct MPT3SAS_ADAPTER *ioc, struct _sas_phy
	*mpt3sas_phy, Mpi2SasPhyPage0_t phy_pg0, struct device *parent_dev);
void mpt3sas_transport_update_links(struct MPT3SAS_ADAPTER *ioc,
	u64 sas_address, u16 handle, u8 phy_number, u8 link_rate,
	struct hba_port *port);
extern struct sas_function_template mpt3sas_transport_functions;
extern struct scsi_transport_template *mpt3sas_transport_template;
void
mpt3sas_transport_del_phy_from_an_existing_port(struct MPT3SAS_ADAPTER *ioc,
	struct _sas_node *sas_node, struct _sas_phy *mpt3sas_phy);
void
mpt3sas_transport_add_phy_to_an_existing_port(struct MPT3SAS_ADAPTER *ioc,
	struct _sas_node *sas_node, struct _sas_phy *mpt3sas_phy,
	u64 sas_address, struct hba_port *port);
#endif 
