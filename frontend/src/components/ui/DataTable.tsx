import { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface Column<T> {
  header: string;
  accessor: keyof T | ((row: T) => ReactNode);
  className?: string;
}

interface DataTableProps<T> {
  data: T[];
  columns: Column<T>[];
  keyExtractor: (row: T) => string | number;
  onRowClick?: (row: T) => void;
}

export function DataTable<T>({ data, columns, keyExtractor, onRowClick }: DataTableProps<T>) {
  return (
    <div className="w-full overflow-x-auto bg-surface border-sentinel rounded-lg shadow-sm">
      <table className="w-full text-sm text-left">
        <thead className="text-xs text-muted uppercase bg-background border-b border-border">
          <tr>
            {columns.map((col, i) => (
              <th key={i} className={cn("px-4 py-3 font-semibold", col.className)}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr
              key={keyExtractor(row)}
              onClick={() => onRowClick?.(row)}
              className={cn(
                "border-b border-border/50 hover:bg-background/50 transition-colors",
                onRowClick ? "cursor-pointer" : "",
                i === data.length - 1 ? "border-none" : ""
              )}
            >
              {columns.map((col, j) => (
                <td key={j} className={cn("px-4 py-3", col.className)}>
                  {typeof col.accessor === "function" ? col.accessor(row) : (row[col.accessor] as ReactNode)}
                </td>
              ))}
            </tr>
          ))}
          {data.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-4 py-8 text-center text-muted">
                No data available
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
