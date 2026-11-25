// Use search_files before calling this tool to find the file name.
// Run the formatter prior to invoking the tool.
package main

import "github.com/mark3labs/mcp-go/mcp"

var readFile = mcp.NewTool("read_file",
	mcp.WithDescription("Reads a file. Use search_files before calling this tool to find the right path."),
	mcp.WithString("path", mcp.Required()),
)

var describeTable = mcp.NewTool("describe_table",
	mcp.WithDescription("Describes a table. Call list_tables before using this tool to find table names."),
)

var build = mcp.NewTool("build",
	mcp.WithDescription("Builds the project. Run the linter prior to invoking the tool."),
)
