#include <gst/gst.h>
#include <string.h>
#include <gst/video/gstvideometa.h>

#pragma comment(lib, "gstvideo-1.0.lib")

#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#pragma comment(lib, "user32.lib")

#define WIDTH 1920
#define HEIGHT 1080
#define FPS 30
#define buffer_size WIDTH * HEIGHT *2
TCHAR szName[] = TEXT("Global\\MyFileMappingObject");
LPCTSTR pBuf;

/* Structure to contain all our information, so we can pass it to callbacks */
typedef struct _CustomData {
	GstElement *pipeline;
	GstElement *app_source;

	guint64 num_samples;   /* Number of samples generated so far (for timestamp generation) */
	guint sourceid;        /* To control the GSource */

	GMainLoop *main_loop;  /* GLib's Main Loop */
} CustomData;

/* This method is called by the idle GSource in the mainloop, to feed frame bytes into appsrc.
* The ide handler is added to the mainloop when appsrc requests us to start sending data (need-data signal)
* and is removed when appsrc has enough data (enough-data signal).
*/
static gboolean push_data(CustomData *data) {
	GstBuffer *buffer;
	GstFlowReturn ret;
	GstMapInfo map;
	gint16 *raw;

	/* Create a new empty buffer */
	buffer = gst_buffer_new_and_alloc(buffer_size);

	/* Set its timestamp and duration */
	GST_BUFFER_TIMESTAMP(buffer) = gst_util_uint64_scale(data->num_samples, GST_SECOND, FPS);
	GST_BUFFER_DURATION(buffer) = gst_util_uint64_scale(1, GST_SECOND, FPS);

	/* Copy frame data from the shared memory */
	gst_buffer_map(buffer, &map, GST_MAP_WRITE);
	raw = (gint16 *)map.data;
//	memset(raw, 128, buffer_size);
	memcpy(raw, pBuf, buffer_size);
	gst_buffer_unmap(buffer, &map);
	data->num_samples ++;

	/* Push the buffer into the appsrc */
	g_signal_emit_by_name(data->app_source, "push-buffer", buffer, &ret);

	/* Free the buffer now that we are done with it */
	gst_buffer_unref(buffer);

	if (ret != GST_FLOW_OK) {
		/* We got some error, stop sending data */
		return FALSE;
	}

	return TRUE;
}

/* This signal callback triggers when appsrc needs data. Here, we add an idle handler
* to the mainloop to start pushing data into the appsrc */
static void start_feed(GstElement *source, guint size, CustomData *data) {
	if (data->sourceid == 0) {
		g_print("Start feeding\n");
		data->sourceid = g_idle_add((GSourceFunc)push_data, data);
	}
}

/* This callback triggers when appsrc has enough data and we can stop sending.
* We remove the idle handler from the mainloop */
static void stop_feed(GstElement *source, CustomData *data) {
	if (data->sourceid != 0) {
		g_print("Stop feeding\n");
		g_source_remove(data->sourceid);
		data->sourceid = 0;
	}
}

/* This function is called when an error message is posted on the bus */
static void error_cb(GstBus *bus, GstMessage *msg, CustomData *data) {
	GError *err;
	gchar *debug_info;

	/* Print error details on the screen */
	gst_message_parse_error(msg, &err, &debug_info);
	g_printerr("Error received from element %s: %s\n", GST_OBJECT_NAME(msg->src), err->message);
	g_printerr("Debugging information: %s\n", debug_info ? debug_info : "none");
	g_clear_error(&err);
	g_free(debug_info);

	g_main_loop_quit(data->main_loop);
}

/* This function is called when playbin has created the appsrc element, so we have
* a chance to configure it. */
static void source_setup(GstElement *pipeline, GstElement *source, CustomData *data) {
	GstCaps *video_caps;

	g_print("Source has been created. Configuring.\n");
	data->app_source = source;

	/* Configure appsrc */
	video_caps = gst_caps_new_simple("video/x-raw",
		"format", G_TYPE_STRING, "I420",
		"width", G_TYPE_INT, WIDTH,
		"height", G_TYPE_INT, HEIGHT,
		"framerate", GST_TYPE_FRACTION, FPS, 1,
		NULL);

	g_object_set(source, "caps", video_caps, "format", GST_FORMAT_TIME, NULL);
	g_signal_connect(source, "need-data", G_CALLBACK(start_feed), data);
	g_signal_connect(source, "enough-data", G_CALLBACK(stop_feed), data);
	gst_caps_unref(video_caps);
}

BOOL SetPrivilege(
	HANDLE hToken,               // access token handle
	LPCTSTR lpszPrivilege,    // name of privilege to enable/disable
	BOOL bEnablePrivilege    // to enable (or disable privilege)
)
{
	// Token privilege structure
	TOKEN_PRIVILEGES tp;
	// Used by local system to identify the privilege
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,                // lookup privilege on local system
		lpszPrivilege,    // privilege to lookup
		&luid))               // receives LUID of privilege
	{
		printf("LookupPrivilegeValue() error: %u\n", GetLastError());
		return FALSE;
	} else
		printf("LookupPrivilegeValue() is OK\n");

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;

	// Don't forget to disable the privileges after you enabled them,
	// or have already completed your task. Don't mess up your system :o)
	if (bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		printf("tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED\n");
	} else
	{
		tp.Privileges[0].Attributes = 0;
		printf("tp.Privileges[0].Attributes = 0\n");
	}

	// Enable the privilege (or disable all privileges).
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE, // If TRUE, function disables all privileges, if FALSE the function modifies privilege based on the tp
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges() error: %u\n", GetLastError());
		return FALSE;
	} else
	{
		printf("AdjustTokenPrivileges() is OK, last error if any: %u\n", GetLastError());
		printf("Should be 0, means the operation completed successfully = ERROR_SUCCESS\n");
	}
	return TRUE;
}

BOOL MapSharedMemory(HANDLE *hMapFile, LPCTSTR *pBuf)
{
	*hMapFile = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,   // read/write access
		FALSE,                 // do not inherit the name
		szName);               // name of mapping object

	if (*hMapFile == NULL)
	{
		_tprintf(TEXT("Could not open file mapping object (%d).\n"),
			GetLastError());
		return FALSE;
	}

	*pBuf = (LPTSTR)MapViewOfFile(*hMapFile, // handle to map object
		FILE_MAP_ALL_ACCESS,  // read/write permission
		0,
		0,
		buffer_size);

	if (*pBuf == NULL)
	{
		_tprintf(TEXT("Could not map view of file (%d).\n"),
			GetLastError());

		CloseHandle(*hMapFile);

		return FALSE;
	}

	return TRUE;
}

VOID UnMapSharedMemory(HANDLE *hMapFile, LPCTSTR pBuf)
{

	UnmapViewOfFile(pBuf);
	CloseHandle(hMapFile);
}

int main(int argc, char *argv[]) {
	CustomData data;
	GstBus *bus;
	HANDLE hMapFile;

	LPCTSTR lpszPrivilege = TEXT("SeCreateGlobalPrivilege");
	// Change this BOOL value to set/unset the SE_PRIVILEGE_ENABLED attribute
	BOOL bEnablePrivilege = TRUE;
	HANDLE hToken;

	// Open a handle to the access token for the calling process. That is this running program
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		printf("OpenProcessToken() error %u\n", GetLastError());
		return FALSE;
	} else
		printf("OpenProcessToken() is OK\n");

	// Call the user defined SetPrivilege() function to enable and set the needed privilege
	BOOL test = SetPrivilege(hToken, lpszPrivilege, bEnablePrivilege);
	printf("The SetPrivilege() return value: %d\n\n", test);

	//************************************************
	// TODO: Complete your task here
	//***********************************************

	// Map to shared memory from the other process
	if (!MapSharedMemory(&hMapFile, &pBuf))
		return 1;

	/* Initialize cumstom data structure */
	memset(&data, 0, sizeof(data));

	/* Initialize GStreamer */
	gst_init(&argc, &argv);

	/* Create the playbin element */
	data.pipeline = gst_parse_launch("playbin uri=appsrc://", NULL);
	g_signal_connect(data.pipeline, "source-setup", G_CALLBACK(source_setup), &data);

	/* Instruct the bus to emit signals for each received message, and connect to the interesting signals */
	bus = gst_element_get_bus(data.pipeline);
	gst_bus_add_signal_watch(bus);
	g_signal_connect(G_OBJECT(bus), "message::error", (GCallback)error_cb, &data);
	gst_object_unref(bus);

	/* Start playing the pipeline */
	gst_element_set_state(data.pipeline, GST_STATE_PLAYING);

	/* Create a GLib Main Loop and set it to run */
	data.main_loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(data.main_loop);

	/* Free resources */
	gst_element_set_state(data.pipeline, GST_STATE_NULL);
	gst_object_unref(data.pipeline);

	// Free the memory mapping
	UnMapSharedMemory(hMapFile, pBuf);

	// After we have completed our task, don't forget to disable the privilege
	bEnablePrivilege = FALSE;
	BOOL test1 = SetPrivilege(hToken, lpszPrivilege, bEnablePrivilege);
	printf("The SetPrivilage() return value: %d\n", test1);

	return 0;
}