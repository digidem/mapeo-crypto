declare module 'compact-encoding-struct' {
  interface CencStruct {
    compile(struct: any): any
    opt(...args: any[]): any
    constant(...args: any[]): any
    header(...args: any[]): any
    getHeader(...args: any[]): any
  }
  const cencS: CencStruct
  export = cencS
}
